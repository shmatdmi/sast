import type { Rule } from "./sast-engine.ts";
import { createHttpRules } from "./sast-rules-http.ts";

// Additional concrete HTTP access paths. Existing API metadata and IDs stay unchanged.
type Channel = { name: string; call: boolean };
const properties = (names: string): Channel[] => names.trim().split(/\s+/).map(name => ({ name, call: false }));
const calls = (names: string): Channel[] => names.trim().split(/\s+/).map(name => ({ name, call: true }));
const channels: Record<string, Channel[]> = {
  HTTPJS: [
    ...properties(`req.payload req.rawBody req.originalUrl req.url req.hostname req.signedCookies
      request.payload request.headers request.cookies request.rawBody request.url request.hostname
      ctx.params ctx.headers ctx.request.query ctx.request.headers ctx.request.rawBody
      ctx.request.url ctx.request.hostname ctx.request.files`),
    ...calls(`req.get req.header req.param request.get request.header request.param ctx.get ctx.cookies.get
      request.json request.text request.formData req.json req.text req.formData
      event.request.json event.request.text event.request.formData
      request.nextUrl.searchParams.get req.nextUrl.searchParams.get c.req.query`),
  ],
  HTTPPY: [
    ...properties(`self.request.arguments self.request.body self.request.headers self.request.query_arguments
      self.request.body_arguments self.request.cookies self.request.path self.request.uri self.request.host
      self.path_args self.path_kwargs request.data request.body request.query_string request.META
      request.url request.path request.host request.rel_url request.match_info`),
    ...calls(`self.get_argument self.get_arguments self.get_query_argument self.get_query_arguments
      self.get_body_argument self.get_body_arguments self.get_cookie
      request.get_json request.get_data request.get_cookie request.get_param request.get_param_as_list
      request.get_param_as_int request.get_header request.get_media request.text request.json request.post
      bottle.request.get_cookie flask.request.get_json`),
  ],
  HTTPPHP: [
    ...calls(`$request->input $request->query $request->post $request->get $request->cookie
      $request->header $request->file $request->getContent $request->getPayload $request->toArray
      $request->getQueryParams $request->getParsedBody $request->getCookieParams $request->getUploadedFiles
      $request->getHeader $request->getHeaderLine $request->getBody $request->getUri
      $request->getServerParams $request->getAttribute
      request()->input request()->query request()->post request()->cookie request()->header
      $this->request->getGet $this->request->getPost $this->request->getCookie
      $this->request->getHeaderLine $this->request->getBody`),
  ],
  HTTPRB: [
    ...properties(`request.body request.raw_post request.query_string request.fullpath request.original_url
      request.url request.path request.host request.headers request.referer request.user_agent
      request.media_type request.authorization request.remote_ip request.ip
      request.content_type request.path_info request.script_name
      env controller.params controller.request.params controller.request.cookies
      controller.request.headers controller.request.body controller.request.query_parameters
      controller.request.request_parameters controller.request.path_parameters
      controller.request.env controller.cookies rack_request.params`),
  ],
};
const escape = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const apiById = new Map<string, string>();

export function getFrameworkRuleApi(id: string): string | undefined {
  return apiById.get(id);
}

export function createFrameworkRules(): Rule[] {
  // One representative per API, with its original CWE, recommendation and language scope.
  const apis = createHttpRules().filter((_, index) => index % 10 === 0);
  return apis.flatMap(base => {
    const family = base.id.replace(/\d+$/, "");
    const apiIndex = (Number(base.id.slice(family.length)) - 1) / 10;
    const api = base.title.split(": HTTP-ввод из ")[0];
    return channels[family].map((channel, channelIndex): Rule => {
      const id = `${family.replace("HTTP", "FW")}${String(apiIndex * channels[family].length + channelIndex + 1).padStart(5, "0")}`;
      apiById.set(id, api);
      const access = channel.call ? "\\s*\\(" : "(?=\\s*(?:->|\\.|\\[|[,)]))";
      // async body readers are also supported when directly awaited in the argument.
      const source = `${channel.call ? "(?:await\\s+)?" : ""}${escape(channel.name)}${access}`;
      return {
        ...base, id,
        title: `${api}: HTTP-ввод из ${channel.name}${channel.call ? "()" : ""}`,
        description: `В ${api} первым аргументом передан HTTP-ввод из ${channel.name}. Это эвристическая проверка прямого доступа: тип объекта, импорт, middleware, валидация и безопасность дополнительных аргументов требуют ручной проверки.`,
        pattern: new RegExp(`(?<![\\w$.:>])${escape(api)}\\s*\\(\\s*${source}`),
      };
    });
  });
}
