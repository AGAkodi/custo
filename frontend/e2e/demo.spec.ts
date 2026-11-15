import { test, expect, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

async function accessibility(page: Page) {
  const result = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  expect(result.violations.map(v => ({ id: v.id, impact: v.impact, nodes: v.nodes.map(n => ({target:n.target, summary:n.failureSummary})) }))).toEqual([]);
}

test("local demo: reset, learn, inspect graph, evaluate, replay", async ({ page }) => {
  const token = process.env.CUSTOS_E2E_TOKEN;
  if (!token) throw new Error("Set CUSTOS_E2E_TOKEN for the isolated local test server");
  await page.goto("/");
  await expect(page.getByText("Graph connected")).toBeVisible();
  await accessibility(page);
  await page.getByRole("link", { name: "Lifecycle review" }).click();
  await page.getByLabel("Reviewer token").fill(token);
  page.once("dialog", dialog => dialog.accept());
  await Promise.all([page.waitForResponse(r => r.url().endsWith("/api/demo/reset") && r.status() === 200), page.getByRole("button", { name: "Reset demo" }).click()]);
  await expect(page.getByRole("button", { name: "Reset demo" })).toBeEnabled();
  await expect(page.getByText("No proposals yet")).toBeVisible();
  await accessibility(page);
  await page.getByRole("link", { name: "Incident lab" }).click();
  await page.getByRole("button", { name: "Run baseline" }).click();
  await expect(page.getByRole("heading", { name: "benign", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Reveal outcome" }).click();
  await expect(page.getByText("distributed credential stuffing", { exact: false }).first()).toBeVisible();
  await page.getByRole("button", { name: "Create review proposal" }).click();
  await expect(page.getByRole("heading", { name: "Lifecycle review" })).toBeVisible();
  await expect(page.getByText("under review", { exact: false }).first()).toBeVisible();
  page.once("dialog", dialog => dialog.accept("Reviewed synthetic evidence and regression"));
  await page.getByRole("button", { name: "approve", exact: true }).click();
  await expect(page.getByText("ACTIVE", { exact: true }).first()).toBeVisible();
  await page.getByRole("link", { name: "Incident lab" }).click();
  await page.getByLabel("Choose a scenario").selectOption("held-out");
  await page.getByRole("button", { name: "Run adaptive" }).click();
  await expect(page.getByRole("heading", { name: "distributed credential stuffing", exact: true })).toBeVisible();
  await expect(page.getByText(/Memory:.*threatmemory:/)).toBeVisible();
  await accessibility(page);
  await page.getByRole("link", { name: "Memory graph" }).click();
  await expect(page.getByText(/nodes .* relationships/)).toBeVisible();
  await expect(page.getByRole("group", { name: /Selected graph relationships/ })).toBeVisible();
  await page.getByText(/Full relationship list/).click();
  await expect(page.getByText("supported by", { exact: false }).first()).toBeVisible();
  await accessibility(page);
  await page.getByRole("link", { name: "Evaluation" }).click();
  await page.getByRole("button", { name: "Run evaluation" }).click();
  await expect(page.getByText(/12 HELD-OUT CASES/)).toBeVisible();
  await expect(page.getByText(/FP 4/).last()).toBeVisible();
  await accessibility(page);
  await page.reload();
  await expect(page.getByText(/12 HELD-OUT CASES/)).toBeVisible();
  await page.getByRole("link", { name: "Lifecycle review" }).click();
  await page.getByLabel("Reviewer token").fill(token);
  page.once("dialog", dialog => dialog.accept());
  await Promise.all([page.waitForResponse(r => r.url().endsWith("/api/demo/reset") && r.status() === 200), page.getByRole("button", { name: "Reset demo" }).click()]);
  await expect(page.getByRole("button", { name: "Reset demo" })).toBeEnabled();
  await expect(page.getByText("No proposals yet")).toBeVisible();
  await page.getByRole("link", { name: "Incident lab" }).click();
  await page.getByRole("button", { name: "Run baseline" }).click();
  await expect(page.getByRole("heading", { name: "benign", exact: true })).toBeVisible();
});

test("mobile navigation and controls remain usable", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Intelligence that learns." })).toBeVisible();
  await page.getByRole("link", { name: "Incident lab" }).click();
  await expect(page.getByLabel("Choose a scenario")).toBeVisible();
  await accessibility(page);
});



test("dataset analysis, Sigma download, and offline SOC preview", async ({ page }) => {
  const token = process.env.CUSTOS_E2E_TOKEN;
  if (!token) throw new Error("Set CUSTOS_E2E_TOKEN for the isolated local test server");
  await page.goto("/lab");
  await page.getByRole("button", { name: "Run baseline" }).click();
  await expect(page.getByText(/Decision ID:/)).toBeVisible();
  const text = await page.getByText(/Decision ID:/).innerText();
  const decision = text.match(/[a-f0-9]{32}/)?.[0];
  expect(decision).toBeTruthy();
  await page.getByRole("link", { name: "Data & SOC" }).click();
  await page.getByLabel("CSV sample").setInputFiles({name:"sample.csv",mimeType:"text/csv",buffer:Buffer.from("dur,spkts,dpkts,sbytes,dbytes,label,attack_cat\n1,100,100,100000001,2,1,Exploits\n")});
  await page.getByRole("button", { name: "Analyze sample" }).click();
  await expect(page.getByText("1 flows analyzed")).toBeVisible();
  await expect(page.getByText("high outbound volume")).toBeVisible();
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("link", { name: /Download Sigma YAML/ }).click();
  expect((await downloadPromise).suggestedFilename()).toBe("custos-single-source.yml");
  await page.getByLabel("Reviewer token for Splunk").fill(token);
  await page.getByLabel("Assessment decision ID").fill(decision!);
  await page.getByRole("button", { name: "Preview handoff" }).click();
  await expect(page.getByText("Destination: not configured")).toBeVisible();
  await page.getByText("Inspect complete payload").click();
  await expect(page.getByText(/"sourcetype": "custos:assessment"/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Send to configured Splunk" })).toBeDisabled();
  await accessibility(page);
});


test("sanitized custom incident proposes thresholds from recorded events", async ({page}) => {
  const token = process.env.CUSTOS_E2E_TOKEN;
  if (!token) throw new Error("Set CUSTOS_E2E_TOKEN for the isolated local test server");
  await page.goto("/review");
  await page.getByLabel("Reviewer token").fill(token);
  page.once("dialog", dialog => dialog.accept());
  await Promise.all([page.waitForResponse(r => r.url().endsWith("/api/demo/reset") && r.status() === 200), page.getByRole("button", { name:"Reset demo" }).click()]);
  await expect(page.getByRole("button", {name:"Reset demo"})).toBeEnabled();
  await page.getByRole("link", {name:"Data & SOC"}).click();
  const events = Array.from({length:28}, (_, i) => ({event_id:`custom-${i}`,timestamp:new Date(Date.UTC(2026,0,1,0,0,i*10)).toISOString(),event_type:"login_failed",source_ip:`192.0.2.${30+i%14}`,account_id:`fictional-${i}`,user_agent:"CustosTest/1",result:"failure",scenario_id:"custom-browser"}));
  await page.getByLabel("Incident JSON").fill(JSON.stringify({incident_id:"custom-browser", events}));
  await page.getByRole("button", {name:"Analyze incident"}).click();
  await expect(page.getByText("Assessment: benign")).toBeVisible();
  await page.getByLabel("Reviewer name").fill("Test analyst");
  await page.getByLabel("Evidence note").fill("Sanitized incident reviewed");
  await page.getByRole("button", {name:"Attest feedback & propose rule"}).click();
  await expect(page.getByRole("status")).toContainText("awaiting review");
  await page.getByRole("link", {name:"Lifecycle review"}).click();
  await expect(page.getByText("Analyst note: Sanitized incident reviewed")).toBeVisible();
  await accessibility(page);
});
