import { test, expect } from "@playwright/test";

test("password-free visitors review independently and reset only their workspace", async ({ browser }) => {
  const first = await browser.newContext();
  const second = await browser.newContext();
  try {
    const a = await first.newPage();
    const b = await second.newPage();
    await Promise.all([a.goto("/review"), b.goto("/review")]);
    await expect(a.getByText("Demo reviewer access")).toBeVisible();
    await expect(a.getByLabel("Reviewer token")).toHaveCount(0);
    await a.getByRole("link", { name: "Incident lab" }).click();
    await a.getByRole("button", { name: "Run baseline" }).click();
    await a.getByRole("button", { name: "Reveal outcome" }).click();
    await a.getByRole("button", { name: "Create review proposal" }).click();
    a.once("dialog", dialog => dialog.accept("Reviewed evidence"));
    await a.getByRole("button", { name: "approve", exact: true }).click();
    await expect(a.getByText("ACTIVE", { exact: true })).toBeVisible();
    await expect(b.getByText("No proposals yet")).toBeVisible();
    b.once("dialog", dialog => dialog.accept());
    await b.getByRole("button", { name: "Reset demo" }).click();
    await expect(b.getByText("No proposals yet")).toBeVisible();
    await a.reload();
    await expect(a.getByText("ACTIVE", { exact: true })).toBeVisible();
  } finally {
    await first.close();
    await second.close();
  }
});
