export function HamburgerToggle({ open, onClick }: {
  open: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      aria-label="Toggle navigation"
      aria-expanded={open}
      className={`flex flex-col items-center justify-center w-8 h-8 gap-1.5 transition-colors duration-200 ${
        open ? "text-amber glow" : "text-dim hover:text-amber/80"
      }`}
    >
      <span className="w-5 h-0.5 bg-current rounded-sm origin-center transition-transform" />
      <span className="w-5 h-0.5 bg-current rounded-sm origin-center transition-transform" />
      <span className="w-5 h-0.5 bg-current rounded-sm origin-center transition-transform" />
    </button>
  );
}
