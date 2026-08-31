import { test, expect } from "@playwright/test";

test("signs in via the IdP's account picker", async ({ page }) => {
  await page.goto("/");
  await page.getByTestId("login").click();

  // on the IdP's picker page
  await expect(page.getByRole("heading", { name: "Sign in as" })).toBeVisible();
  await page.getByRole("link", { name: "alice" }).click();

  // back in the app, with claims from the id_token
  await expect(page.getByTestId("user")).toHaveText("Signed in as Alice");
  await expect(page.getByTestId("claims")).toContainText("alice@example.com");
});

test("login_hint skips the picker entirely", async ({ page }) => {
  await page.goto("/");
  await page.getByTestId("username").fill("bob");
  await page.getByTestId("login").click();
  await expect(page.getByTestId("user")).toHaveText("Signed in as Bob");
});

test("userinfo, token refresh, and sign-out", async ({ page }) => {
  await page.goto("/");
  await page.getByTestId("username").fill("alice");
  await page.getByTestId("login").click();
  await expect(page.getByTestId("user")).toHaveText("Signed in as Alice");

  await page.getByTestId("userinfo").click();
  await expect(page.getByTestId("userinfo-result")).toContainText(
    "alice@example.com",
  );

  await page.getByTestId("refresh").click();
  await expect(page.getByTestId("status")).toHaveText("tokens refreshed");

  await page.getByTestId("logout").click();
  await expect(page.getByTestId("login")).toBeVisible();

  // the IdP session ended too: signing in again shows the picker
  await page.getByTestId("login").click();
  await expect(page.getByRole("heading", { name: "Sign in as" })).toBeVisible();
});

test("the IdP session signs the user back in without the picker", async ({
  page,
}) => {
  await page.goto("/");
  await page.getByTestId("login").click();
  await page.getByRole("link", { name: "alice" }).click();
  await expect(page.getByTestId("user")).toHaveText("Signed in as Alice");

  await page.evaluate(() => {
    sessionStorage.clear();
    localStorage.clear();
  });
  await page.reload();
  await expect(page.getByTestId("login")).toBeVisible();

  await page.getByTestId("login").click();
  await expect(page.getByTestId("user")).toHaveText("Signed in as Alice");
});

test("an unknown login_hint is rejected by the IdP", async ({ page }) => {
  await page.goto("/");
  await page.getByTestId("username").fill("mallory");
  await page.getByTestId("login").click();
  await expect(page.getByText("login_hint does not match")).toBeVisible();
});
