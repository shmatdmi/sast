"use client";

import { useState } from "react";
import { LockIcon, ShieldIcon } from "./icons";

export default function LoginPage() {
  const [username, setUsername] = useState(""); const [password, setPassword] = useState("");
  const [error, setError] = useState(""); const [loading, setLoading] = useState(false);
  const submit = async (event: React.FormEvent) => {
    event.preventDefault(); setLoading(true); setError("");
    try { const response = await fetch("/api/auth/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ username, password }) }); const result = await response.json() as { error?: string }; if (!response.ok) throw new Error(result.error); window.location.reload(); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Не удалось войти"); setLoading(false); }
  };
  return <main className="login-page"><section className="login-card">
    <div className="login-brand"><span className="brand-mark"><ShieldIcon size={25} /></span><span>CODE<strong>SENTRY</strong></span></div>
    <div className="login-heading"><span><LockIcon size={17} /></span><h1>Вход в систему</h1><p>Авторизуйтесь, чтобы открыть центр анализа безопасности.</p></div>
    <form onSubmit={submit}><label>Логин<input autoFocus autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} required /></label><label>Пароль<input type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required /></label>{error && <div className="login-error" role="alert">{error}</div>}<button disabled={loading}>{loading ? "Проверяем…" : "Войти"}</button></form>
    <small>Доступ к сервису предоставляется администратором</small>
  </section></main>;
}
