import CodeMirror from "@uiw/react-codemirror";
import { yaml } from "@codemirror/lang-yaml";
import { json } from "@codemirror/lang-json";
import { EditorView } from "@codemirror/view";

const dark = typeof window !== "undefined" && window.matchMedia("(prefers-color-scheme: dark)").matches;

export function CodeEditor({ value, onChange, lang, height = "320px", label }: {
  value: string; onChange: (v: string) => void; lang: "yaml" | "json"; height?: string; label: string;
}) {
  return (
    <div className="overflow-hidden rounded border border-line" aria-label={label}>
      <CodeMirror value={value} height={height} theme={dark ? "dark" : "light"} onChange={onChange}
        extensions={[lang === "yaml" ? yaml() : json(), EditorView.lineWrapping]}
        basicSetup={{ lineNumbers: true, foldGutter: false }} />
    </div>
  );
}
