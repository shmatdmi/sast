/** Supported analysis groups, shared by the scanner, uploads and dashboard. */
export const supportedLanguages = [
  { id: "javascript", label: "JavaScript", extensions: ["js", "jsx", "mjs", "cjs", "vue", "svelte"] },
  { id: "typescript", label: "TypeScript", extensions: ["ts", "tsx", "mts", "cts"] },
  { id: "python", label: "Python", extensions: ["py"] },
  { id: "java", label: "Java", extensions: ["java"] },
  { id: "php", label: "PHP", extensions: ["php"] },
  { id: "go", label: "Go", extensions: ["go"] },
  { id: "csharp", label: "C#", extensions: ["cs"] },
  { id: "ruby", label: "Ruby", extensions: ["rb"] },
  { id: "kotlin", label: "Kotlin", extensions: ["kt", "kts"] },
  { id: "rust", label: "Rust", extensions: ["rs"] },
  { id: "swift", label: "Swift", extensions: ["swift"] },
  { id: "scala", label: "Scala", extensions: ["scala"] },
  { id: "shell", label: "Shell", extensions: ["sh", "bash", "zsh"] },
  { id: "config", label: "Конфигурация", extensions: ["json", "yaml", "yml", "xml", "env", "conf", "ini", "toml", "tf", "hcl", "plist"] },
  { id: "c", label: "C", extensions: ["c", "h"] },
  { id: "cpp", label: "C++", extensions: ["cc", "cpp", "cxx", "hh", "hpp", "hxx"] },
  { id: "dart", label: "Dart", extensions: ["dart"] },
  { id: "elixir", label: "Elixir", extensions: ["ex", "exs"] },
  { id: "lua", label: "Lua", extensions: ["lua"] },
  { id: "powershell", label: "PowerShell", extensions: ["ps1", "psm1", "psd1"] },
] as const;

export const supportedLanguageCount = supportedLanguages.length;
export const languageByExtension: Record<string, string> = Object.fromEntries(
  supportedLanguages.flatMap(({ id, extensions }) => extensions.map((extension) => [extension, id])),
);
export const languageLabels: Record<string, string> = {
  auto: "Автоопределение",
  ...Object.fromEntries(supportedLanguages.map(({ id, label }) => [id, label])),
  unknown: "Универсальный",
  multiple: "Несколько языков",
};
