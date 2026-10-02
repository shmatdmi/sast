import { extractZip, MAX_ARCHIVE_BYTES } from "../../../lib/archive";
import { requireApiUser } from "../../../lib/auth";
import { scanFiles } from "../../../lib/sast-engine";
import { saveScanResult } from "../../../lib/save-scan";

const RELEASE_PATTERN = /^[A-Za-z]{2,4}-(?:[1-9][0-9]{0,3})$/;
const MAX_MULTIPART_BYTES = MAX_ARCHIVE_BYTES + 1024 * 1024;

function textField(form: FormData, name: string) {
  const value = form.get(name);
  return typeof value === "string" ? value.trim() : "";
}

export async function POST(request: Request) {
  const auth = await requireApiUser(request);
  if ("response" in auth) return auth.response;

  if (!request.headers.get("content-type")?.toLowerCase().startsWith("multipart/form-data")) {
    return Response.json({ error: "Ожидается multipart/form-data" }, { status: 415 });
  }
  const contentLength = Number(request.headers.get("content-length") ?? 0);
  if (contentLength > MAX_MULTIPART_BYTES) {
    return Response.json({ error: "Запрос слишком большой" }, { status: 413 });
  }

  try {
    const form = await request.formData();
    const archive = form.get("archive");
    const release = textField(form, "release");
    if (!(archive instanceof File) || archive.size === 0) {
      return Response.json({ error: "Добавьте ZIP-файл в поле archive" }, { status: 400 });
    }
    if (archive.size > MAX_ARCHIVE_BYTES) {
      return Response.json({ error: "ZIP-архив больше 10 МБ" }, { status: 413 });
    }
    if (!archive.name.toLowerCase().endsWith(".zip")) {
      return Response.json({ error: "Поле archive должно содержать ZIP-файл" }, { status: 400 });
    }
    if (!RELEASE_PATTERN.test(release)) {
      return Response.json({ error: "Некорректный релиз; пример: test-456" }, { status: 400 });
    }
    const suppliedProjectName = textField(form, "projectName");
    const projectName = suppliedProjectName || archive.name.replace(/\.zip$/i, "");
    if (!projectName || projectName.length > 512) {
      return Response.json({ error: "Название проекта должно содержать от 1 до 512 символов" }, { status: 400 });
    }

    const extracted = extractZip(new Uint8Array(await archive.arrayBuffer()));
    const result = scanFiles(extracted.files);
    const created = await saveScanResult(projectName, release, result);

    return Response.json({
      scanId: created.id,
      createdAt: created.createdAt,
      projectName,
      release,
      skippedFiles: extracted.skippedFiles,
      ...result,
    }, { status: 201 });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Не удалось проверить ZIP-архив";
    if (/ZIP|архив|файл|исходник|путь|МБ/.test(message)) {
      return Response.json({ error: message }, { status: 400 });
    }
    console.error("Failed to scan uploaded archive", error);
    return Response.json({ error: "Не удалось проверить ZIP-архив" }, { status: 500 });
  }
}
