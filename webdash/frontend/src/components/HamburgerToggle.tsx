export function HamburgerToggle({ open, onClick }: {
  open: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label="Toggle navigation"
      aria-expanded={open}
      className={`flex flex-col items-center justify-center w-8 h-8 gap-1.5 transition-colors duration-200 ${
        open ? "text-amber glow" : "text-dim hover:text-amber/80"
      }`}
    >
      {[0, 1, 2].map((i) => (
        <span key={i} className="w-5 h-0.5 bg-current rounded-sm" />
      ))}
    </button>
  );
}
