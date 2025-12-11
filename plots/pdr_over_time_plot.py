from pathlib import Path
import csv

import matplotlib.pyplot as plt

# load pdr csv
def load_series(csv_path: Path):
    times = []
    pdrs = []
    with csv_path.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                times.append(float(row["time"]))
                pdrs.append(float(row["pdr_pct"]))
            except (KeyError, ValueError):
                continue
    return times, pdrs


def plot():
    plt.rcParams.update({
        "text.usetex": True,
        "font.family": "serif",
        "font.serif": ["Times New Roman", "Times"],
        "font.size": 9,
        "axes.labelsize": 9,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
        "legend.fontsize": 8,
    })

    csv_path = Path(__file__).resolve().parents[1] / "logs" / "pdr_over_time.csv"
    if not csv_path.exists():
        print(f"missing {csv_path}")
        return

    times, pdrs = load_series(csv_path)
    # only show samples after certain time
    clipped = [(t, p) for t, p in zip(times, pdrs) if t >= 50]
    if clipped:
        times, pdrs = zip(*clipped)
        times = list(times)
        pdrs = list(pdrs)

    if not times:
        print("no PDR samples to plot")
        return

    fig, ax = plt.subplots(figsize=(3.45, 2.35), dpi=300)
    ax.plot(times, pdrs, linewidth=1.2)
    ax.set_xlabel("Simulation Time (s)")
    ax.set_ylabel("PDR (\%)")
    ax.set_ylim(0, 100)
    ax.grid(True, linestyle="--", linewidth=0.4, alpha=0.7)

    fig.tight_layout()
    output_dir = Path(__file__).parent / "figures"
    output_dir.mkdir(parents=True, exist_ok=True)
    png_path = output_dir / "pdr_over_time.png"
    fig.savefig(png_path, dpi=600, bbox_inches="tight")
    print(f"saved {png_path}")


if __name__ == "__main__":
    plot()
