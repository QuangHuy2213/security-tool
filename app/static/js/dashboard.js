document.addEventListener("DOMContentLoaded", () => {
    const refreshButton = document.getElementById("refreshButton");

    if (refreshButton) {
        refreshButton.addEventListener("click", () => {
            refreshButton.disabled = true;
            refreshButton.textContent = "↻ Đang làm mới...";
            window.location.reload();
        });
    }

    setInterval(() => {
        fetch("/health")
            .then(response => {
                if (!response.ok) console.warn("Security Tool không phản hồi.");
            })
            .catch(() => console.warn("Không thể kết nối Security Tool."));
    }, 30000);
});