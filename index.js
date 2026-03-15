// index.js (root)
const resultEl = document.getElementById("result");
const staticPreview = document.getElementById("staticPreview");
const staticList = document.getElementById("staticList");
const apiKeyInput = document.getElementById("apiKey");

const base = window.location.origin;

// static files available in repo under /static_preview/
const staticFiles = [
  "serverdeploy_api/test.js",
  "serverdeploy_api/manifest.js",
  "serverdeploy_api/download.js",
  "manifest.json",
  "sample.gds"
];

function populateStaticList(){
  staticFiles.forEach(f=>{
    const opt = document.createElement("option");
    opt.value = f;
    opt.textContent = f;
    staticList.appendChild(opt);
  });
}
populateStaticList();

document.getElementById("btnLoadStatic").addEventListener("click", async ()=>{
  const f = staticList.value;
  try{
    const r = await fetch(`/static_preview/${f}`);
    if(!r.ok) throw new Error("Not found");
    const text = await r.text();
    staticPreview.textContent = text;
  }catch(e){
    staticPreview.textContent = "Error loading static preview: " + e;
  }
});

document.getElementById("btn-view-static").addEventListener("click", ()=>{
  // open folder in new tab for quick manual browsing
  window.open('/static_preview/', '_blank');
});

document.getElementById("btn-test-api").addEventListener("click", async ()=>{
  const key = apiKeyInput.value.trim();
  const headers = key ? { "x-api-key": key } : {};
  try{
    const r = await fetch(`${base}/serverdeploy/api/test`, { headers });
    const txt = await r.text();
    resultEl.textContent = `HTTP ${r.status}\n\n${txt}`;
  }catch(e){ resultEl.textContent = "Error: " + e; }
});

document.getElementById("btn-manifest-api").addEventListener("click", async ()=>{
  const key = apiKeyInput.value.trim();
  const url = new URL(`${base}/serverdeploy/api/manifest`);
  if (!key) url.searchParams.set("api_key", "your-secret-key"); else url.searchParams.set("api_key", key);
  try{
    const r = await fetch(url.toString());
    const txt = await r.text();
    resultEl.textContent = `HTTP ${r.status}\n\n${txt}`;
  }catch(e){ resultEl.textContent = "Error: " + e; }
});

document.getElementById("btn-download-api").addEventListener("click", async ()=>{
  const key = apiKeyInput.value.trim();
  const filename = "sample.gds";
  const url = new URL(`${base}/serverdeploy/api/download/${encodeURIComponent(filename)}`);
  if (key) url.searchParams.set("api_key", key); else url.searchParams.set("api_key", "your-secret-key");
  // for download, open in new tab so browser downloads the file
  window.open(url.toString(), "_blank");
});
