import { requireApiUser } from "../../../lib/auth";
import { scanFiles } from "../../../lib/sast-engine";
import { saveScanResult } from "../../../lib/save-scan";
import { parseScanJson, readScanJson, ScanInputError } from "../../../lib/scan-json";
import { appVersion } from "../../../lib/version";

export async function POST(request: Request) {
  const auth = await requireApiUser(request);
  if ("response" in auth) return auth.response;
  try {
    const { projectName, release, files } = parseScanJson(await readScanJson(request));
    const result = scanFiles(files);
    const created = await saveScanResult(projectName, release, result);
    return Response.json({
      scanId: created.id,
      createdAt: created.createdAt,
      version: appVersion,
      projectName,
      release,
      ...result,
    }, { status: 201 });
  } catch (error) {
    if (error instanceof ScanInputError) return Response.json({ error: error.message }, { status: error.status });
    console.error("Failed to scan JSON sources", error);
    return Response.json({ error: "Не удалось проверить исходники" }, { status: 500 });
  }
}
