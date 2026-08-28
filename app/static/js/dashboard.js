document.addEventListener("DOMContentLoaded", function () {

    const refreshButton =
        document.querySelector(".refresh-button");

    if (refreshButton) {

        refreshButton.addEventListener(
            "click",
            function () {
                window.location.reload();
            }
        );

    }

});