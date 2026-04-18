import matplotlib.pyplot as plt

tiers = ["Tier 1\n(1–1K)", "Tier 2\n(1K–10K)", "Tier 3\n(10K–100K)", "Tier 4\n(100K–1M)"]
adoption_rates = [44.30, 43.97, 35.29, 0.01]

plt.figure(figsize=(8, 5))
bars = plt.bar(tiers, adoption_rates)

plt.ylabel("DKIM Adoption Rate (%)")
plt.xlabel("Ranking Tier")
plt.title("DKIM Adoption by Ranking Tier")

for bar, value in zip(bars, adoption_rates):
    plt.text(bar.get_x() + bar.get_width()/2, bar.get_height(),
             f"{value:.2f}%", ha='center', va='bottom', fontsize=10)

plt.ylim(0, 50)
plt.tight_layout()

plt.savefig("dkim_adoption_by_tier.png", dpi=300)

plt.show()