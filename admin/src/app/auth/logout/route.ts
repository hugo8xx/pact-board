import { NextResponse } from "next/server";
import { config } from "@/lib/config";
import { SESSION_COOKIE } from "@/lib/session";

export async function POST() {
  const response = NextResponse.redirect(new URL("/signed-out", config.appUrl), 303);
  response.cookies.delete(SESSION_COOKIE);
  return response;
}
