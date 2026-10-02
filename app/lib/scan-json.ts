import { isSupportedSourceFile, MAX_ARCHIVE_FILES, MAX_ARCHIVE_UNPACKED_BYTES, MAX_SOURCE_FILE_BYTES, type SourceFile } from "./archive.ts";

export const MAX_SCAN_JSON_BYTES = 25 * 1024 * 1024;

export class ScanInputError extends Error {
  status: number;
  constructor(message: string, status = 400) {
    super(message);
    this.status = status;
  }
}

export async function readScanJson(request: Request): Promise<unknown> {
  const mediaType = request.headers.get("content-type")?.split(";")[0].trim().toLowerCase();
  if (mediaType !== "application/json") throw new ScanInputError("Ожидается application/json", 415);
  if (Number(request.headers.get("content-length") ?? 0) > MAX_SCAN_JSON_BYTES) {
    throw new ScanInputError("JSON-запрос больше 25 МБ", 413);
  }
  if (!request.body) throw new ScanInputError("Тело JSON-запроса пустое");
  const reader = request.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let size = 0;
  let text = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_SCAN_JSON_BYTES) {
        await reader.cancel();
        throw new ScanInputError("JSON-запрос больше 25 МБ", 413);
      }
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
  } catch (error) {
    if (error instanceof ScanInputError) throw error;
    throw new ScanInputError("Не удалось прочитать JSON в кодировке UTF-8");
  } finally {
    reader.releaseLock();
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new ScanInputError("Некорректный JSON");
  }
}

export function parseScanJson(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ScanInputError("Ожидается JSON-объект с projectName, release и files");
  }
  const payload = value as Record<string, unknown>;
  if (typeof payload.projectName !== "string" || !payload.projectName.trim() || payload.projectName.trim().length > 512) {
    throw new ScanInputError("Название проекта должно содержать от 1 до 512 символов");
  }
  if (typeof payload.release !== "string" || !/^[A-Za-z]{2,4}-(?:[1-9][0-9]{0,3})$/.test(payload.release.trim())) {
    throw new ScanInputError("Некорректный релиз; пример: test-456");
  }
  if (!Array.isArray(payload.files) || payload.files.length === 0) {
    throw new ScanInputError("Добавьте непустой массив files с полями name и code");
  }
  if (payload.files.length > MAX_ARCHIVE_FILES) throw new ScanInputError("В запросе больше 500 файлов", 413);
  const names = new Set<string>();
  const encoder = new TextEncoder();
  let totalBytes = 0;
  const files: SourceFile[] = payload.files.map((item: unknown, index: number) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new ScanInputError(`Некорректный файл files[${index}]`);
    const file = item as Record<string, unknown>;
    if (typeof file.name !== "string" || !file.name.trim() || file.name.length > 512 || typeof file.code !== "string") {
      throw new ScanInputError(`Файл files[${index}] должен содержать name (1–512 символов) и строку code`);
    }
    const name = file.name.trim().replace(/\\/g, "/");
    if (/^[a-z]:|^\/|[\u0000-\u001f\u007f]/i.test(name) || name.split("/").some((part) => !part || part === "." || part === "..")) {
      throw new ScanInputError(`Небезопасный путь файла: ${name}`);
    }
    if (!isSupportedSourceFile(name)) throw new ScanInputError(`Неподдерживаемый тип файла: ${name}`);
    if (names.has(name)) throw new ScanInputError(`Повторяющийся путь файла: ${name}`);
    names.add(name);
    if (file.code.includes("\0")) throw new ScanInputError(`Файл содержит бинарные данные: ${name}`);
    const size = encoder.encode(file.code).byteLength;
    if (size > MAX_SOURCE_FILE_BYTES) throw new ScanInputError(`Файл больше 1 МБ: ${name}`, 413);
    totalBytes += size;
    if (totalBytes > MAX_ARCHIVE_UNPACKED_BYTES) throw new ScanInputError("Исходники занимают больше 20 МБ", 413);
    return { name, code: file.code, size };
  });
  return { projectName: payload.projectName.trim(), release: payload.release.trim(), files };
}
