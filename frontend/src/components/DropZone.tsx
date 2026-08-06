import { useRef, useState } from "react";

interface Props {
  busy: boolean;
  error: string | null;
  onFile: (file: File) => void;
}

/* The upload control is the whole home screen, so it is a labelled drop target
 * rather than a button with a hint. Clicking anywhere in it opens the picker. */
export default function DropZone({ busy, error, onFile }: Props) {
  const [over, setOver] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  function take(files: FileList | null) {
    const file = files?.[0];
    if (file && !busy) onFile(file);
  }

  return (
    <div
      className={[
        "drop",
        over && !busy ? "drop--over" : "",
        busy ? "drop--busy" : "",
      ]
        .filter(Boolean)
        .join(" ")}
      onDragOver={(event) => {
        event.preventDefault();
        setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={(event) => {
        event.preventDefault();
        setOver(false);
        take(event.dataTransfer.files);
      }}
    >
      <div className="drop__scan" aria-hidden="true" />

      <input
        ref={input}
        type="file"
        className="visually-hidden"
        onChange={(event) => {
          take(event.target.files);
          event.target.value = "";
        }}
      />

      <p className="drop__title">
        {busy ? "Reading the file" : "Drop a file here"}
      </p>

      <p className="drop__hint">
        {busy ? (
          "This takes a moment. The file is being read, not run."
        ) : (
          <>
            or{" "}
            <button
              type="button"
              className="drop__pick"
              onClick={() => input.current?.click()}
            >
              choose a file
            </button>{" "}
            from this computer
          </>
        )}
      </p>

      <p className="drop__note label">Executables · Documents · Archives</p>

      {error && (
        <p className="drop__error" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}
