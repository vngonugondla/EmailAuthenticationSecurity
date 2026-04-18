import matplotlib.pyplot as plt

labels = ["google", "selector1", "default", "Others"]
counts = [11758, 11007, 6555, 36287 - (11758 + 11007 + 6555)]

plt.figure(figsize=(6, 6))

plt.pie(
    counts,
    labels=labels,
    autopct='%1.1f%%',
    startangle=140
)

plt.title("DKIM Selector Distribution")

plt.tight_layout()
plt.savefig("dkim_selector_pie_chart.png", dpi=300)
plt.show()