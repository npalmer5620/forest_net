from pathlib import Path
import statistics

import matplotlib.pyplot as plt

# raw averages from multiple runs
JOIN_TIME_AVERAGES = {
    25: [8.4383, 6.0940, 6.3415, 8.0653],
    50: [9.7097, 7.8578, 8.0444, 12.4869, 9.3016],
    100: [9.5689, 10.1555, 15.6420, 11.2639],
    200: [9.5535, 10.2800, 10.0758, 10.2150],
    150: [11.5446, 10.5670, 9.7522, 13.0021],
    250: [9.6853],
    300: [12.9575],
}

# compute mean per size
NETWORK_SIZES = sorted(JOIN_TIME_AVERAGES.keys())
AVERAGE_JOIN_TIMES = [statistics.mean(JOIN_TIME_AVERAGES[size]) for size in NETWORK_SIZES]

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

    fig, ax = plt.subplots(figsize=(3.45, 2.35), dpi=300)
    ax.plot(NETWORK_SIZES, AVERAGE_JOIN_TIMES, marker="o", linewidth=1.2, markersize=4)
    ax.set_xlabel("Network Size (nodes)")
    ax.set_ylabel("Average Join Time (s)")
    ax.grid(True, linestyle="--", linewidth=0.4, alpha=0.7)
    ax.text(0.02, 0.98, r"$E_0 = 0.25$ mAh, $T_s = 1$s, $P_{loss} = 0.01$", transform=ax.transAxes,
            fontsize=7, ha='left', va='top')

    fig.tight_layout()
    output_dir = Path(__file__).parent / "figures"
    output_dir.mkdir(parents=True, exist_ok=True)

    png_path = output_dir / "average_join_time_vs_network_size.png"
    fig.savefig(png_path, dpi=600, bbox_inches="tight")
    print(f"saved {png_path}")


if __name__ == "__main__":
    plot()
