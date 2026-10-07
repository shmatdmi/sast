import assert from "node:assert/strict";
import test from "node:test";
import { supportedLanguages, supportedLanguageCount, languageByExtension, languageLabels } from "../app/lib/sast-languages.ts";
import { detectLanguage } from "../app/lib/sast-engine.ts";
import { isSupportedSourceFile } from "../app/lib/archive.ts";

test("dashboard coverage and selectors agree with the language registry", () => {
  assert.equal(supportedLanguageCount, 20);
  assert.equal(new Set(supportedLanguages.map(language => language.id)).size, supportedLanguageCount);
  assert.ok(languageLabels.auto);
  assert.ok(languageLabels.unknown);
  assert.ok(languageLabels.multiple);
  const extensions = supportedLanguages.flatMap(language => [...language.extensions]);
  assert.equal(new Set(extensions).size, extensions.length);
});
for (const { id, label, extensions } of supportedLanguages) {
  test(`${label}: every advertised extension is accepted and detected in both cases`, () => {
    assert.equal(languageLabels[id], label);
    for (const extension of extensions) {
      assert.equal(languageByExtension[extension], id);
      for (const filename of [`src/file.${extension}`, `SRC/FILE.${extension.toUpperCase()}`]) {
        assert.equal(isSupportedSourceFile(filename), true, filename);
        // Uppercase .C is the established C++ filename convention.
        const expected = id === "c" && filename.endsWith(".C") ? "cpp" : id;
        assert.equal(detectLanguage(filename, ""), expected, filename);
      }
    }
  });
}
test("configuration special names and unsupported binary formats are distinguished", () => {
  for (const filename of ["Dockerfile", "src/Dockerfile", ".env", "src/.env"]) {
    assert.equal(isSupportedSourceFile(filename), true);
    assert.equal(detectLanguage(filename, ""), "config");
  }
  for (const filename of ["file.png", "file.zip", "file.exe", "file.pdf"]) assert.equal(isSupportedSourceFile(filename), false);
});
