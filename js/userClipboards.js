"use strict";

(function ($) {
  var page = 1;

  $(() => {
    if ($("body").is(".user.index") && $("#clipboards").length) {
      loadClipboards();
    }
  });

  function startActivity() {
    $("#clipboardsActivityIndicator").removeClass("hidden");
  }

  function endActivity() {
    $("#clipboardsActivityIndicator").addClass("hidden");
  }

  function changePage(amount) {
    page = page + amount;
    getAndAppendItems($("#clipboardsRows"), page);
  }

  function constructRowElement(rowData) {
    var row = $("<tr>");
    var td = $("<td></td>").append(
      $("<a></a>").attr("href", rowData.loadUrl).text(rowData.password)
    );
    var td2 = $("<td></td>").text(rowData.createdAt);
    var td3 = $("<td></td>");

    rowData.counts.forEach(function (item) {
      td3.append($("<div></div>").text(item.type + ": " + item.count));
    });

    var deleteLabel = $("#clipboards").data("delete-label");
    var td4 = $('<td class="text-end"></td>').append(
      $('<button type="button" class="btn atom-btn-white btn-sm"></button>')
        .attr("title", deleteLabel)
        .data("password", rowData.password)
        .append('<i class="fas fa-trash" aria-hidden="true"></i>')
        .append($('<span class="visually-hidden"></span>').text(deleteLabel))
        .click(deleteClipboard)
    );

    return row.append(td).append(td2).append(td3).append(td4);
  }

  function deleteClipboard() {
    var password = $(this).data("password");
    var $clipboards = $("#clipboards");
    var confirmMessage = $clipboards
      .data("delete-confirm")
      .replace("%1%", password);

    if (!window.confirm(confirmMessage)) {
      return;
    }

    startActivity();
    $.ajax({
      url: window.location.pathname + "/user/deleteClipboard",
      type: "POST",
      dataType: "json",
      data: {
        id: password,
        _csrf_token: $clipboards.attr("data-csrf-token"),
      },
      success: function () {
        // Go back a page if the deleted clipboard was the last one on it
        if ($("#clipboardsRows tr").length <= 1 && page > 1) {
          changePage(-1);
        } else {
          changePage(0);
        }
      },
      error: function (xhr) {
        endActivity();
        if (xhr.responseJSON && xhr.responseJSON.error) {
          window.alert(xhr.responseJSON.error);
        }
      },
    });
  }

  function getAndAppendItems(tbodyEl, page) {
    var pagedUrl = window.location.pathname + "/user/clipboards?page=" + page;

    startActivity();
    $.ajax({
      url: pagedUrl,
      dataType: "json",
      success: function (data) {
        // Empty table body then add rows using results
        tbodyEl.empty();

        data.results.forEach(function (item) {
          tbodyEl.append(constructRowElement(item));
        });

        // Hide or show previous and next page buttons
        $("#clipboardsPreviousButton").toggleClass("hidden", page <= 1);
        $("#clipboardsNextButton").toggleClass("hidden", data.pages <= page);

        // Only show saved clipboards section if data exists
        $("#clipboards").toggleClass("hidden", !data.pages);

        endActivity();
      },
    });
  }

  function loadClipboards() {
    $("#clipboardsPreviousButton").click(function () {
      changePage(-1);
    });

    $("#clipboardsNextButton").click(function () {
      changePage(1);
    });

    // Load first page
    changePage(0);
  }
})(jQuery);
