import { unzipSync } from "fflate";

export const acceptedSourceExtensions = [
  "js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts", "py", "java", "php", "go", "cs", "rb",
  "kt", "kts", "rs", "swift", "scala", "sh", "bash", "zsh", "json", "yaml", "yml", "xml", "env", "txt",
];
const acceptedSourceNames = ["dockerfile"];
const ignoredDirectories = new Set([".git", "node_modules", "vendor", "dist", "build", ".next", ".vinext"]);

export const MAX_SOURCE_FILE_BYTES = 1024 * 1024;
export const MAX_ARCHIVE_BYTES = 10 * 1024 * 1024;
export const MAX_ARCHIVE_UNPACKED_BYTES = 20 * 1024 * 1024;
export const MAX_ARCHIVE_FILES = 500;
export type SourceFile = { name: string; code: string; size: number };
export type ArchiveContents = { files: SourceFile[]; skippedFiles: number };
class ArchiveValidationError extends Error {}

export function isSupportedSourceFile(name: string) {
  const basename = name.split(/[\\/]/).pop()?.toLowerCase() ?? "";
  const extension = basename.split(".").pop() ?? "";
  return acceptedSourceExtensions.includes(extension) || acceptedSourceNames.includes(basename);
}
function isSafeArchivePath(name: string) {
  const normalized = name.replace(/\\/g, "/");
  return !normalized.startsWith("/") && !/^[a-z]:\//i.test(normalized) && !normalized.split("/").includes("..");
}
function isIgnoredPath(name: string) {
  return name.replace(/\\/g, "/").split("/").some((part) => ignoredDirectories.has(part.toLowerCase()));
}
function looksBinary(data: Uint8Array) {
  const length = Math.min(data.length, 8_000);
  for (let index = 0; index < length; index += 1) if (data[index] === 0) return true;
  return false;
}

export function extractZip(data: Uint8Array): ArchiveContents {
  if (data.byteLength > MAX_ARCHIVE_BYTES) throw new Error("ZIP-архив больше 10 МБ.");
  let selectedFiles = 0;
  let unpackedBytes = 0;
  let skippedFiles = 0;
  let entries: Record<string, Uint8Array>;
  try {
    entries = unzipSync(data, { filter: (entry) => {
      if (!isSafeArchivePath(entry.name)) throw new ArchiveValidationError(`Небезопасный путь в архиве: ${entry.name}`);
      if (entry.name.endsWith("/") || isIgnoredPath(entry.name) || !isSupportedSourceFile(entry.name)) {
        if (!entry.name.endsWith("/")) skippedFiles += 1;
        return false;
      }
      if (entry.originalSize > MAX_SOURCE_FILE_BYTES) { skippedFiles += 1; return false; }
      selectedFiles += 1;
      unpackedBytes += entry.originalSize;
      if (selectedFiles > MAX_ARCHIVE_FILES) throw new ArchiveValidationError(`В архиве больше ${MAX_ARCHIVE_FILES} поддерживаемых файлов.`);
      if (unpackedBytes > MAX_ARCHIVE_UNPACKED_BYTES) throw new ArchiveValidationError("Распакованные исходники занимают больше 20 МБ.");
      return true;
    }});
  } catch (error) {
    if (error instanceof ArchiveValidationError) throw error;
    throw new Error("Не удалось распаковать ZIP-архив. Возможно, файл повреждён или защищён паролем.");
  }
  const decoder = new TextDecoder("utf-8");
  const files = Object.entries(entries).sort(([left], [right]) => left.localeCompare(right)).flatMap(([name, contents]) => {
    if (looksBinary(contents)) { skippedFiles += 1; return []; }
    return [{ name: name.replace(/\\/g, "/"), code: decoder.decode(contents), size: contents.byteLength }];
  });
  if (!files.length) throw new Error("В ZIP-архиве нет поддерживаемых файлов с исходным кодом.");
  return { files, skippedFiles };
}
