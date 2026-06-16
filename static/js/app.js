document.querySelectorAll("[data-confirm]").forEach((form) => {
  form.addEventListener("submit", (event) => {
    if (!window.confirm(form.dataset.confirm)) event.preventDefault();
  });
});

const searchInput = document.querySelector("[data-table-search]");
if (searchInput) {
  searchInput.addEventListener("input", () => {
    const query = searchInput.value.toLowerCase();
    document.querySelectorAll(".searchable").forEach((element) => {
      if (element.tagName === "TABLE") {
        element.querySelectorAll("tbody tr").forEach((row) => {
          row.hidden = !row.textContent.toLowerCase().includes(query);
        });
      } else {
        element.hidden = !element.textContent.toLowerCase().includes(query);
      }
    });
  });
}

const chartDataElement = document.getElementById("chart-data");
if (chartDataElement && window.Chart) {
  const chartData = JSON.parse(chartDataElement.textContent);
  const colors = ["#40e0b2", "#50a7df", "#ffc857", "#a98bff", "#ff7c91", "#8fa4ba"];
  const makeChart = (id, values, type = "doughnut") => {
    const labels = Object.keys(values);
    const data = Object.values(values);
    if (!labels.length) return;
    new Chart(document.getElementById(id), {
      type,
      data: { labels, datasets: [{ data, backgroundColor: colors, borderColor: "#101d2e" }] },
      options: {
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: "#cbd8e6", boxWidth: 10 } } },
        scales: type === "bar" ? {
          x: { ticks: { color: "#8fa4ba" }, grid: { color: "#23364e" } },
          y: { ticks: { color: "#8fa4ba", precision: 0 }, grid: { color: "#23364e" } }
        } : undefined
      }
    });
  };
  makeChart("dnsChart", chartData.dns);
  makeChart("httpChart", chartData.http, "bar");
  makeChart("headersChart", chartData.headers);
}
