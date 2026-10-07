import type { Rule } from "./sast-engine.ts";
import { createHttpRules } from "./sast-rules-http.ts";
import { createFrameworkRules } from "./sast-rules-framework.ts";

const apis = new Map<string, string>();
export const getExpressionRuleApi = (id: string): string | undefined => apis.get(id);
const escape = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const literal = `(?:"[^"\\\\\r\n]*"|'[^'\\\\\r\n]*')`;
const tail = `(?:\\s*(?:\\.[A-Za-z_]\\w*|->[A-Za-z_]\\w*|\\[(?:${literal}|\\d{1,10})\\]))*`;

/** Concrete expression forms; each definition retains its original API/source metadata. */
export function createExpressionRules(): Rule[] {
  return [...createHttpRules(), ...createFrameworkRules()].flatMap(base => {
    const [api, channel] = base.title.split(": HTTP-ввод из ");
    const isCall = channel.endsWith("()");
    const name = isCall ? channel.slice(0, -2) : channel;
    const source = `${isCall ? "(?:await\\s+)?" : ""}${escape(name)}${isCall ? `\\s*\\(\\s*(?:${literal})?\\s*\\)` : ""}${tail}`;
    const php = base.languages.includes("php");
    const python = base.languages.includes("python");
    const ruby = base.languages.includes("ruby");
    const operator = php ? "\\." : "\\+";
    const fallback = php ? "\\?\\?" : python ? "or\\b" : "\\|\\|";
    const grouped = `\\(\\s*${source}\\s*\\)`;
    const end = "(?=\\s*[,)])";
    const forms = [
      { key: "GROUP", label: "ввод в скобках", expression: grouped + end },
      { key: "GROUP_PREFIX", label: "конкатенация с вводом в скобках", expression: `${literal}\\s*${operator}\\s*${grouped}${end}` },
      { key: "GROUP_SUFFIX", label: "суффикс после ввода в скобках", expression: `${grouped}\\s*${operator}\\s*${literal}${end}` },
      { key: "FALLBACK", label: "ввод со значением по умолчанию", expression: `${source}\\s*${fallback}\\s*${literal}${end}` },
    ];
    // The 4000 original HTTP pairs have no interpolation definitions in CMP.
    if (base.id.startsWith("HTTP")) {
      let expression: string;
      if (php) expression = `"[^"{}\\\\\r\n]*\\{\\s*${source}\\s*\\}[^"{}\\\\\r\n]*"${end}`;
      else if (ruby) expression = `"[^"#{}\\\\\r\n]*#\\{\\s*${source}\\s*\\}[^"#{}\\\\\r\n]*"${end}`;
      else if (python) expression = `(?:f"[^"{}\\\\\r\n]*\\{\\s*${source}\\s*\\}[^"{}\\\\\r\n]*"|f'[^'{}\\\\\r\n]*\\{\\s*${source}\\s*\\}[^'{}\\\\\r\n]*')${end}`;
      else expression = "`[^`$\\\\\r\n]*\\$\\{\\s*" + source + "\\s*\\}[^`$\\\\\r\n]*`" + end;
      forms.push({ key: "INTERPOLATION", label: "строковая интерполяция", expression });
    }
    return forms.map(({ key, label, expression }): Rule => {
      const id = `EXPR_${base.id}_${key}`;
      apis.set(id, api);
      return { ...base, id, title: `${api}: ${label}, HTTP-ввод из ${channel}`,
        description: `HTTP-ввод из ${channel} передан первым аргументом ${api}: ${label}. Скобки, конкатенация и значение по умолчанию не устанавливают доверие к вводу. Типы, импорты и предшествующая валидация требуют ручной проверки.`,
        pattern: new RegExp(`(?<![\\w$.:>])${escape(api)}\\s*\\(\\s*${expression}`) };
    });
  });
}
