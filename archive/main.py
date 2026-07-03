"""
Secure Password Generator
=========================
A modern desktop application for generating cryptographically secure
passwords using Python's `secrets` module.

Modules:
    - tkinter / ttk : GUI construction
    - secrets       : cryptographically secure random number generator
    - string        : character set constants
    - os            : file path handling
    - datetime      : timestamping saved passwords
    - re            : input validation
"""

import os
import re
import secrets
import string
import datetime
import tkinter as tk
from tkinter import ttk, messagebox

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
APP_TITLE = "Secure Password Generator"
APP_VERSION = "1.0.0"

MIN_LENGTH = 4
MAX_LENGTH = 128
DEFAULT_LENGTH = 16
DEFAULT_COUNT = 1

OUTPUT_FILE = "generated_passwords.txt"

# Dark modern palette
BG_DARK = "#1e1e2e"
BG_PANEL = "#2a2a3d"
BG_INPUT = "#1a1a27"
FG_PRIMARY = "#e4e4f1"
FG_SECONDARY = "#a9a9c2"
ACCENT = "#7c5cff"
ACCENT_HOVER = "#9277ff"
DANGER = "#ff5c7a"
SUCCESS = "#5cffb0"
INFO = "#5cc8ff"
WARN = "#ffb45c"

# Strength colors
STRENGTH_COLORS = {
    "Weak": DANGER,
    "Medium": WARN,
    "Strong": SUCCESS,
    "Very Strong": INFO,
}

CHAR_SETS = {
    "uppercase": string.ascii_uppercase,
    "lowercase": string.ascii_lowercase,
    "numbers": string.digits,
    "special": string.punctuation,
}

CHAR_LABELS = {
    "uppercase": "Uppercase Letters (A-Z)",
    "lowercase": "Lowercase Letters (a-z)",
    "numbers": "Numbers (0-9)",
    "special": "Special Characters (!@#...)",
}


# ---------------------------------------------------------------------------
# Strength evaluation
# ---------------------------------------------------------------------------
def calculate_strength(password: str) -> str:
    """
    Classify a password as Weak / Medium / Strong / Very Strong.

    Heuristic combines length with the diversity of character categories
    present in the password.
    """
    if not password:
        return "Weak"

    categories = 0
    if re.search(r"[A-Z]", password):
        categories += 1
    if re.search(r"[a-z]", password):
        categories += 1
    if re.search(r"[0-9]", password):
        categories += 1
    if re.search(r"[^A-Za-z0-9]", password):
        categories += 1

    length = len(password)
    score = length * categories

    if length < 8 or categories < 2 or score < 16:
        return "Weak"
    if length < 12 or score < 36:
        return "Medium"
    if length < 16 or score < 64:
        return "Strong"
    return "Very Strong"


# ---------------------------------------------------------------------------
# Password generation
# ---------------------------------------------------------------------------
def generate_password(length: int, categories: list) -> str:
    """
    Generate a single cryptographically secure password.

    Guarantees that every selected category appears at least once, then
    randomizes the final order with `secrets.SystemRandom`.
    """
    # Start with one mandatory character from each selected category
    password_chars = [secrets.choice(CHAR_SETS[cat]) for cat in categories]

    # Build the pool of remaining characters from the union of selected sets
    pool = "".join(CHAR_SETS[cat] for cat in categories)

    # Fill the rest of the password with cryptographically secure choices
    password_chars += [secrets.choice(pool) for _ in range(length - len(categories))]

    # Shuffle using the secrets-backed SystemRandom for unbiased ordering
    secrets.SystemRandom().shuffle(password_chars)

    return "".join(password_chars)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def validate_inputs(length_text: str, count_text: str, selected: list) -> tuple:
    """
    Validate user inputs.

    Returns (ok, length, count, error_message).
    """
    if not length_text.strip():
        return False, 0, 0, "Password length is required."

    if not length_text.isdigit():
        return False, 0, 0, "Password length must be a whole number."

    length = int(length_text)
    if length < MIN_LENGTH:
        return False, 0, 0, f"Password length must be at least {MIN_LENGTH}."
    if length > MAX_LENGTH:
        return False, 0, 0, f"Password length cannot exceed {MAX_LENGTH}."

    if not count_text.strip():
        return False, 0, 0, "Number of passwords is required."

    if not count_text.isdigit():
        return False, 0, 0, "Number of passwords must be a whole number."

    count = int(count_text)
    if count < 1:
        return False, 0, 0, "Number of passwords must be at least 1."
    if count > 50:
        return False, 0, 0, "Cannot generate more than 50 passwords at once."

    if not selected:
        return False, 0, 0, "Select at least one character category."

    return True, length, count, ""


# ---------------------------------------------------------------------------
# Main application
# ---------------------------------------------------------------------------
class SecurePasswordGeneratorApp:
    """Main application window and controller."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), OUTPUT_FILE)

        # Tk variables
        self.length_var = tk.StringVar(value=str(DEFAULT_LENGTH))
        self.count_var = tk.StringVar(value=str(DEFAULT_COUNT))
        self.category_vars = {
            "uppercase": tk.BooleanVar(value=True),
            "lowercase": tk.BooleanVar(value=True),
            "numbers": tk.BooleanVar(value=True),
            "special": tk.BooleanVar(value=False),
        }
        self.strength_var = tk.StringVar(value="—")
        self.status_var = tk.StringVar(value="Ready")

        # Style the ttk widgets
        self._configure_style()

        # Build the layout
        self._build_gui()

        # Window close handler
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        # Center window on screen
        self._center_window(780, 760)

    # ------------------------------------------------------------------ GUI
    def _configure_style(self) -> None:
        """Apply the dark modern theme to ttk widgets."""
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        self.root.configure(bg=BG_DARK)
        style.configure("TFrame", background=BG_DARK)
        style.configure("Panel.TFrame", background=BG_PANEL, relief="flat")
        style.configure("TLabel", background=BG_DARK, foreground=FG_PRIMARY,
                        font=("Segoe UI", 10))
        style.configure("Panel.TLabel", background=BG_PANEL, foreground=FG_PRIMARY,
                        font=("Segoe UI", 10))
        style.configure("Title.TLabel", background=BG_DARK, foreground=FG_PRIMARY,
                        font=("Segoe UI", 22, "bold"))
        style.configure("Subtitle.TLabel", background=BG_DARK, foreground=FG_SECONDARY,
                        font=("Segoe UI", 10))
        style.configure("Section.TLabel", background=BG_PANEL, foreground=FG_PRIMARY,
                        font=("Segoe UI", 11, "bold"))
        style.configure("Status.TLabel", background=BG_PANEL, foreground=FG_SECONDARY,
                        font=("Segoe UI", 9))
        style.configure("Tip.TLabel", background=BG_PANEL, foreground=FG_SECONDARY,
                        font=("Segoe UI", 9))
        style.configure("Strength.TLabel", background=BG_PANEL, foreground=FG_SECONDARY,
                        font=("Segoe UI", 10, "bold"))

        style.configure("TEntry", fieldbackground=BG_INPUT, foreground=FG_PRIMARY,
                        insertcolor=FG_PRIMARY, borderwidth=0, relief="flat")
        style.configure("TCheckbutton", background=BG_PANEL, foreground=FG_PRIMARY,
                        focuscolor=BG_PANEL, font=("Segoe UI", 10))
        style.map("TCheckbutton",
                  background=[("active", BG_PANEL)],
                  foreground=[("active", FG_PRIMARY)])

        style.configure("Accent.TButton", background=ACCENT, foreground="#ffffff",
                        font=("Segoe UI", 10, "bold"), borderwidth=0,
                        focusthickness=0, padding=(18, 10))
        style.map("Accent.TButton",
                  background=[("active", ACCENT_HOVER), ("disabled", "#4a4a6a")])

        style.configure("Ghost.TButton", background=BG_PANEL, foreground=FG_PRIMARY,
                        font=("Segoe UI", 10), borderwidth=1, padding=(14, 8))
        style.map("Ghost.TButton",
                  background=[("active", "#3a3a55")],
                  foreground=[("active", FG_PRIMARY)])

    def _center_window(self, width: int, height: int) -> None:
        """Center the application window on the user's screen."""
        self.root.update_idletasks()
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        x = (screen_w - width) // 2
        y = (screen_h - height) // 2
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        self.root.minsize(720, 720)

    def _build_gui(self) -> None:
        """Assemble every widget inside the main window."""
        self.root.title(f"{APP_TITLE}  •  v{APP_VERSION}")
        self.root.resizable(True, True)

        # ------------------ Header ------------------
        header = ttk.Frame(self.root, style="TFrame", padding=(24, 20, 24, 8))
        header.pack(fill="x")
        ttk.Label(header, text="🔐  Secure Password Generator", style="Title.TLabel").pack(anchor="w")
        ttk.Label(header, text="Generate cryptographically secure passwords instantly.",
                  style="Subtitle.TLabel").pack(anchor="w", pady=(4, 0))

        # ------------------ Options panel ------------------
        options = ttk.Frame(self.root, style="Panel.TFrame", padding=(20, 18))
        options.pack(fill="x", padx=24, pady=(8, 8))

        ttk.Label(options, text="Options", style="Section.TLabel").grid(
            row=0, column=0, columnspan=4, sticky="w", pady=(0, 12))

        # Length + Count side by side
        ttk.Label(options, text="Password Length", style="Panel.TLabel").grid(
            row=1, column=0, sticky="w", padx=(0, 6))
        self.length_spin = tk.Spinbox(
            options, from_=MIN_LENGTH, to=MAX_LENGTH, width=8,
            textvariable=self.length_var, font=("Segoe UI", 11),
            bg=BG_INPUT, fg=FG_PRIMARY, buttonbackground=BG_PANEL,
            relief="flat", bd=0, highlightthickness=1,
            highlightbackground=ACCENT, highlightcolor=ACCENT, insertbackground=FG_PRIMARY,
        )
        self.length_spin.grid(row=1, column=1, sticky="w", padx=(0, 24), ipady=4)

        ttk.Label(options, text="Number of Passwords", style="Panel.TLabel").grid(
            row=1, column=2, sticky="w", padx=(0, 6))
        self.count_spin = tk.Spinbox(
            options, from_=1, to=50, width=8,
            textvariable=self.count_var, font=("Segoe UI", 11),
            bg=BG_INPUT, fg=FG_PRIMARY, buttonbackground=BG_PANEL,
            relief="flat", bd=0, highlightthickness=1,
            highlightbackground=ACCENT, highlightcolor=ACCENT, insertbackground=FG_PRIMARY,
        )
        self.count_spin.grid(row=1, column=3, sticky="w", ipady=4)

        # Range hint
        ttk.Label(options, text=f"({MIN_LENGTH} – {MAX_LENGTH})", style="Panel.TLabel",
                  foreground=FG_SECONDARY).grid(row=2, column=1, sticky="w", pady=(2, 0))
        ttk.Label(options, text="(1 – 50)", style="Panel.TLabel",
                  foreground=FG_SECONDARY).grid(row=2, column=3, sticky="w", pady=(2, 0))

        # Character categories
        ttk.Label(options, text="Character Categories", style="Panel.TLabel").grid(
            row=3, column=0, columnspan=4, sticky="w", pady=(18, 8))

        categories_frame = ttk.Frame(options, style="Panel.TFrame")
        categories_frame.grid(row=4, column=0, columnspan=4, sticky="w")

        for idx, (key, label) in enumerate(CHAR_LABELS.items()):
            cb = ttk.Checkbutton(
                categories_frame, text=label, variable=self.category_vars[key],
                style="TCheckbutton",
            )
            cb.grid(row=0, column=idx, padx=(0, 22), sticky="w")

        # Action buttons row
        actions = ttk.Frame(options, style="Panel.TFrame")
        actions.grid(row=5, column=0, columnspan=4, sticky="we", pady=(20, 0))

        self.generate_btn = ttk.Button(actions, text="⚙  Generate Password",
                                       style="Accent.TButton", command=self.on_generate)
        self.generate_btn.grid(row=0, column=0, padx=(0, 10))

        self.copy_btn = ttk.Button(actions, text="📋  Copy",
                                   style="Ghost.TButton", command=self.on_copy,
                                   state="disabled")
        self.copy_btn.grid(row=0, column=1, padx=(0, 10))

        self.save_btn = ttk.Button(actions, text="💾  Save to File",
                                   style="Ghost.TButton", command=self.on_save,
                                   state="disabled")
        self.save_btn.grid(row=0, column=2, padx=(0, 10))

        self.clear_btn = ttk.Button(actions, text="✖  Clear",
                                    style="Ghost.TButton", command=self.on_clear)
        self.clear_btn.grid(row=0, column=3)

        actions.columnconfigure(0, weight=0)
        actions.columnconfigure(1, weight=0)
        actions.columnconfigure(2, weight=0)
        actions.columnconfigure(3, weight=0)

        # ------------------ Output panel ------------------
        output_panel = ttk.Frame(self.root, style="Panel.TFrame", padding=(20, 18))
        output_panel.pack(fill="both", expand=True, padx=24, pady=(0, 8))

        top_row = ttk.Frame(output_panel, style="Panel.TFrame")
        top_row.pack(fill="x")

        ttk.Label(top_row, text="Generated Passwords", style="Section.TLabel").pack(
            side="left")
        self.strength_label = tk.Label(
            top_row, text="Strength: —", font=("Segoe UI", 10, "bold"),
            bg=BG_PANEL, fg=FG_SECONDARY, padx=10, pady=2,
        )
        self.strength_label.pack(side="right")

        # Text output
        self.output_text = tk.Text(
            output_panel, height=10, font=("Consolas", 12),
            bg=BG_INPUT, fg=FG_PRIMARY, insertbackground=FG_PRIMARY,
            relief="flat", bd=0, highlightthickness=1,
            highlightbackground="#3a3a55", highlightcolor=ACCENT,
            wrap="word", padx=14, pady=12,
        )
        self.output_text.pack(fill="both", expand=True, pady=(12, 0))
        self.output_text.configure(state="disabled")

        # ------------------ Tips panel ------------------
        tips = ttk.Frame(self.root, style="Panel.TFrame", padding=(20, 16))
        tips.pack(fill="x", padx=24, pady=(0, 8))
        ttk.Label(tips, text="Password Safety Tips", style="Section.TLabel").pack(anchor="w")
        tips_text = (
            "✔  Never reuse passwords across sites\n"
            "✔  Use a unique password for every account\n"
            "✔  Minimum 12 characters recommended\n"
            "✔  Never share passwords over email or chat"
        )
        ttk.Label(tips, text=tips_text, style="Tip.TLabel", justify="left").pack(
            anchor="w", pady=(8, 0))

        # ------------------ Status bar ------------------
        status_bar = ttk.Frame(self.root, style="Panel.TFrame", padding=(20, 10))
        status_bar.pack(fill="x", side="bottom")
        ttk.Label(status_bar, textvariable=self.status_var, style="Status.TLabel").pack(
            side="left")
        ttk.Label(status_bar, text=f"Output file: {OUTPUT_FILE}", style="Status.TLabel").pack(
            side="right")

    # ------------------------------------------------------------------ Actions
    def on_generate(self) -> None:
        """Validate inputs and generate the requested passwords."""
        length_text = self.length_var.get()
        count_text = self.count_var.get()
        selected = [k for k, v in self.category_vars.items() if v.get()]

        ok, length, count, err = validate_inputs(length_text, count_text, selected)
        if not ok:
            messagebox.showerror("Invalid Input", err)
            self._set_status(err)
            return

        passwords = [generate_password(length, selected) for _ in range(count)]

        # Display
        self._set_output(passwords)

        # Strength of the first password
        first_strength = calculate_strength(passwords[0])
        self._set_strength(first_strength, length, len(selected))

        # Update counts / state
        if count == 1:
            self.current_password = passwords[0]
        else:
            self.current_password = passwords[0]
            self.current_passwords = passwords
        self.copy_btn.state(["!disabled"])
        self.save_btn.state(["!disabled"])

        if count == 1:
            self._set_status(f"Generated 1 password ({first_strength}).")
        else:
            self._set_status(f"Generated {count} passwords (showing first: {first_strength}).")

    def on_copy(self) -> None:
        """Copy the first generated password to the system clipboard."""
        pwd = getattr(self, "current_password", None)
        if not pwd:
            messagebox.showwarning("Nothing to Copy", "Generate a password first.")
            return
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(pwd)
            self.root.update()  # keeps clipboard alive after window closes
            self._set_status("Password copied to clipboard ✔")
            messagebox.showinfo("Copied", "Password copied to clipboard.")
        except tk.TclError as exc:
            messagebox.showerror("Clipboard Error", str(exc))

    def on_save(self) -> None:
        """Append generated passwords (with timestamp + strength) to the output file."""
        passwords = getattr(self, "current_passwords", None)
        if not passwords:
            single = getattr(self, "current_password", None)
            if single:
                passwords = [single]
        if not passwords:
            messagebox.showwarning("Nothing to Save", "Generate a password first.")
            return

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = []
        for pwd in passwords:
            strength = calculate_strength(pwd)
            lines.append(f"Date: {timestamp}\nPassword: {pwd}\nStrength: {strength}\n{'-' * 40}\n")

        try:
            with open(self.output_path, "a", encoding="utf-8") as fh:
                fh.write("\n".join(lines))
        except OSError as exc:
            messagebox.showerror("Save Failed", f"Could not write to file:\n{exc}")
            return

        self._set_status(f"Saved {len(passwords)} password(s) to {OUTPUT_FILE} ✔")
        messagebox.showinfo("Saved", f"{len(passwords)} password(s) appended to\n{self.output_path}")

    def on_clear(self) -> None:
        """Reset all input fields and the output area."""
        self.length_var.set(str(DEFAULT_LENGTH))
        self.count_var.set(str(DEFAULT_COUNT))
        for var in self.category_vars.values():
            var.set(False)
        self.category_vars["uppercase"].set(True)
        self.category_vars["lowercase"].set(True)
        self.category_vars["numbers"].set(True)
        self.category_vars["special"].set(False)

        self._set_output([])
        self._set_strength("—", 0, 0)

        self.current_password = None
        self.current_passwords = []
        self.copy_btn.state(["disabled"])
        self.save_btn.state(["disabled"])

        self._set_status("Cleared. Ready to generate.")

    def _on_close(self) -> None:
        """Handle window-close event cleanly."""
        self.root.destroy()

    # ------------------------------------------------------------------ Helpers
    def _set_output(self, passwords: list) -> None:
        """Replace the contents of the output text widget."""
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", "end")
        if passwords:
            for idx, pwd in enumerate(passwords, start=1):
                self.output_text.insert("end", f"{idx:>2}.  {pwd}\n")
        else:
            self.output_text.insert("end", "  (no passwords generated yet)\n")
        self.output_text.configure(state="disabled")

    def _set_strength(self, label: str, length: int = 0, categories: int = 0) -> None:
        """Update the strength indicator label and color."""
        if label == "—":
            self.strength_label.config(text="Strength: —", fg=FG_SECONDARY)
            return
        color = STRENGTH_COLORS.get(label, FG_SECONDARY)
        self.strength_label.config(text=f"Strength: {label}", fg=color)

    def _set_status(self, text: str) -> None:
        """Update the bottom status bar."""
        self.status_var.set(text)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    """Launch the Secure Password Generator application."""
    root = tk.Tk()
    SecurePasswordGeneratorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
