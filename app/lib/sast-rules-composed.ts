import type { Rule } from "./sast-engine.ts";
import { createHttpRules } from "./sast-rules-http.ts";
import { createFrameworkRules } from "./sast-rules-framework.ts";

const apis = new Map<string, string>();
export const getComposedRuleApi = (id: string): string | undefined => apis.get(id);
const escape = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
// Literal/accessor syntax deliberately excludes nested calls and multiline strings.
const literal = `(?:"[^"\\\\\r\n]*"|'[^'\\\\\r\n]*')`;
const tail = `(?:\\s*(?:\\.[A-Za-z_]\\w*|->[A-Za-z_]\\w*|\\[(?:${literal}|\\d{1,10})\\]))*`;

export function createComposedRules(): Rule[] {
  return [...createHttpRules(), ...createFrameworkRules()].flatMap(base => {
    const [api, channel] = base.title.split(": HTTP-ввод из ");
    const isCall = channel.endsWith("()");
    const name = isCall ? channel.slice(0, -2) : channel;
    const source = `${isCall ? "(?:await\\s+)?" : ""}${escape(name)}${isCall ? `\\s*\\(\\s*(?:${literal})?\\s*\\)` : ""}${tail}`;
    const operator = base.languages.includes("php") ? "\\." : "\\+";
    const forms = [
      { key: "PREFIX", label: "строковый префикс", expression: `${literal}\\s*${operator}\\s*${source}(?=\\s*[,)+.])` },
      { key: "SUFFIX", label: "строковый суффикс", expression: `${source}\\s*${operator}\\s*${literal}(?=\\s*[,)+.])` },
    ];
    // 6000 framework pairs per language add interpolation coverage (12000 definitions).
    if (base.id.startsWith("FWJS")) forms.push({ key: "TEMPLATE", label: "template literal", expression: "`[^`$\\\\\r\n]*\\$\\{\\s*" + source + "\\s*\\}[^`$\\\\\r\n]*`(?=\\s*[,)])" });
    if (base.id.startsWith("FWPY")) forms.push({ key: "FSTRING", label: "f-string", expression: `(?:f"[^"{}\\\\\r\n]*\\{\\s*${source}\\s*\\}[^"{}\\\\\r\n]*"|f'[^'{}\\\\\r\n]*\\{\\s*${source}\\s*\\}[^'{}\\\\\r\n]*')(?=\\s*[,)])` });
    return forms.map(({ key, label, expression }): Rule => {
      const id = `CMP_${base.id}_${key}`;
      apis.set(id, api);
      return { ...base, id, title: `${api}: ${label}, HTTP-ввод из ${channel}`,
        description: `HTTP-ввод из ${channel} входит в составную строку первого аргумента ${api}. Эвристика требует проверки типов, импортов, валидации и условий эксплуатации.`,
        pattern: new RegExp(`(?<![\\w$.:>])${escape(api)}\\s*\\(\\s*${expression}`) };
    });
  });
}
