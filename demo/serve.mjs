import { createServer } from "node:http";
import { readFile } from "node:fs/promises";

const port = Number(process.env.PORT ?? 3000);
const page = {
  url: new URL("index.html", import.meta.url),
  type: "text/html; charset=utf-8",
};
const files = {
  "/oidc-client-ts.min.js": {
    url: new URL(
      "node_modules/oidc-client-ts/dist/browser/oidc-client-ts.min.js",
      import.meta.url,
    ),
    type: "text/javascript; charset=utf-8",
  },
};

createServer(async (req, res) => {
  const file = files[req.url] ?? page;
  try {
    const body = await readFile(file.url);
    res.setHeader("content-type", file.type);
    res.end(body);
  } catch {
    res.statusCode = 500;
    res.end(`cannot read ${file.url.pathname}`);
  }
}).listen(port, () => console.log(`demo app on http://localhost:${port}`));
