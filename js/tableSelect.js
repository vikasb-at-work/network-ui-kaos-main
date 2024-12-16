$(function() {
	//If check_all checked then check all table rows
	$("#check_all").on("click", function () {
		if ($("input:checkbox").prop("checked")) {
			$("input:checkbox[name='row-check']").prop("checked", true);
			$("#samurai_table tr").addClass("highlightRow");
		} else {
			$("input:checkbox[name='row-check']").prop("checked", false);
			$("#samurai_table tr").removeClass("highlightRow");
		}
	});

	$("#samurai_table tr").on("click", function() {
		if ($(this).parent("thead").length) { } else {
				$(this).toggleClass("highlightRow");
				if ($(this).find("input:checkbox").prop("checked")) {
					$(this).find("input:checkbox").prop("checked", false);
				} else {
					$(this).find("input:checkbox").prop("checked", true);
				}
		}
	});

	// Check each table row checkbox
	$("input:checkbox[name='row-check']").on("change", function () {
		var total_check_boxes = $("input:checkbox[name='row-check']").length;
		var total_checked_boxes = $("input:checkbox[name='row-check']:checked").length;

		// If all checked manually then check check_all checkbox
		if (total_check_boxes === total_checked_boxes) {
			$("#check_all").prop("checked", true);
		}
		else {
			$("#check_all").prop("checked", false);
		}
	});

	$("#samurai_table tbody tr td span").on("click", function() {
		$(this).parent().parent().parent().toggleClass("collapsibleRow");
		$(this).parent().parent().parent().toggleClass("expandedGroup");
		$(this).toggleClass("plus");
		$(this).toggleClass("minus");
		$row = $(this).parent().parent()
		$row.toggleClass("highlightRow");
                if ($row.find("input:checkbox").prop("checked")) {
                    $row.find("input:checkbox").prop("checked", false);
                } else {
                    $row.find("input:checkbox").prop("checked", true);
                }

	});
});
