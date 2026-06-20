const confirmModalElement = document.getElementById("confirmActionModal");
const confirmModal = confirmModalElement && window.bootstrap
  ? new bootstrap.Modal(confirmModalElement)
  : null;
const confirmTitle = document.getElementById("confirmActionTitle");
const confirmMessage = document.getElementById("confirmActionMessage");
const confirmButton = document.getElementById("confirmActionButton");
let pendingConfirmedForm = null;
let pendingSubmitter = null;

const attachSubmitterValue = (form, submitter) => {
  form.querySelectorAll("[data-submitter-shadow]").forEach((input) => input.remove());
  if (!submitter?.name) return;

  const input = document.createElement("input");
  input.type = "hidden";
  input.name = submitter.name;
  input.value = submitter.value;
  input.dataset.submitterShadow = "true";
  form.appendChild(input);
};

const submitConfirmedForm = (form, submitter) => {
  form.dataset.confirmed = "true";
  attachSubmitterValue(form, submitter);
  markFormBusy(form);

  if (typeof form.submit === "function") {
    HTMLFormElement.prototype.submit.call(form);
  } else {
    form.requestSubmit();
  }
};

const markFormBusy = (form) => {
  if (!form.dataset.busyLabel) return;

  form.querySelectorAll("button[type='submit']").forEach((button) => {
    const text = button.querySelector("[data-busy-text]");
    const spinner = button.querySelector("[data-busy-spinner]");
    button.disabled = true;
    button.classList.add("is-busy");
    if (text) text.textContent = form.dataset.busyLabel;
    if (spinner) spinner.classList.remove("d-none");
  });
};

document.querySelectorAll("form").forEach((form) => {
  form.addEventListener("submit", (event) => {
    if (form.dataset.confirm && form.dataset.confirmed !== "true") {
      event.preventDefault();
      pendingSubmitter = event.submitter || null;

      if (!confirmModal) {
        submitConfirmedForm(form, pendingSubmitter);
        return;
      }

      pendingConfirmedForm = form;
      confirmTitle.textContent = pendingSubmitter?.dataset.confirmTitle || form.dataset.confirmTitle || "Confirm action";
      confirmMessage.textContent = pendingSubmitter?.dataset.confirmBody || form.dataset.confirmBody || form.dataset.confirm;
      confirmButton.textContent = pendingSubmitter?.dataset.confirmButton || form.dataset.confirmButton || "Confirm";
      confirmModal.show();
      return;
    }

    markFormBusy(form);
  });
});

if (confirmButton) {
  confirmButton.addEventListener("click", () => {
    if (!pendingConfirmedForm) return;
    const form = pendingConfirmedForm;
    const submitter = pendingSubmitter;
    pendingConfirmedForm = null;
    pendingSubmitter = null;
    confirmModal.hide();
    submitConfirmedForm(form, submitter);
  });
}

if (confirmModalElement) {
  confirmModalElement.addEventListener("hidden.bs.modal", () => {
    pendingConfirmedForm = null;
    pendingSubmitter = null;
  });
}

document.querySelectorAll("[data-select-all]").forEach((checkbox) => {
  checkbox.addEventListener("change", () => {
    document.querySelectorAll(checkbox.dataset.selectAll).forEach((target) => {
      target.checked = checkbox.checked;
    });
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
