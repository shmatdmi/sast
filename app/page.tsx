import SastWorkspace from "./components/SastWorkspace";
import LoginPage from "./components/LoginPage";
import { headers } from "next/headers";
import { getUserFromCookie } from "./lib/auth";

export default async function Home() {
  const user = await getUserFromCookie((await headers()).get("cookie"));
  return user ? <SastWorkspace user={user} /> : <LoginPage />;
}
