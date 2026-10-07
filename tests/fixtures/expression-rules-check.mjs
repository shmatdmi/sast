import assert from 'node:assert/strict';
import {createExpressionRules} from '../../app/lib/sast-rules-expressions.ts';
const language=process.argv[2];
const rules=createExpressionRules().filter(r=>r.languages.includes(language));
let count=0;
for(const rule of rules) {
 const [api,details]=rule.title.split(': ');
 const channel=details.split('HTTP-ввод из ')[1];
 const name=channel.endsWith('()')?channel.slice(0,-2):channel;
 const source=channel.endsWith('()')?`${name}('value')`:`${name}['value']`;
 const op=language==='php'?'.':'+';
 const fallback=language==='php'?'??':language==='python'?'or':'||';
 let expression=`(${source})`;
 if(rule.id.endsWith('_GROUP_PREFIX')) expression=`'prefix' ${op} (${source})`;
 if(rule.id.endsWith('_GROUP_SUFFIX')) expression=`(${source}) ${op} 'suffix'`;
 if(rule.id.endsWith('_FALLBACK')) expression=`${source} ${fallback} 'default'`;
 if(rule.id.endsWith('_INTERPOLATION')) {
  if(language==='javascript') expression='`prefix${'+source+'}suffix`';
  if(language==='python') expression='f"prefix{'+source+'}suffix"';
  if(language==='php') expression='"prefix{'+source+'}suffix"';
  if(language==='ruby') expression='"prefix#{'+source+'}suffix"';
 }
 assert.ok(rule.pattern.test(`${api}(${expression})`),rule.id);
 for(const code of [`${api}(validate(${expression}))`,`${api}('fixed', ${expression})`,`unrelated${api}(${expression})`,`${api}(${expression.replace(name,'trusted')})`]) assert.ok(!rule.pattern.test(code),`${rule.id}: ${code}`);
 assert.equal(rule.confidence,'medium');
 assert.ok(rule.recommendation.length>30&&rule.references.length);
 count++;
}
console.log(JSON.stringify({language,count}));
