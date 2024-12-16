$.when( $.ready).then(function() {
	y = getParameterByName('year');
    if (y != null && y != "") {
//        $("#year").addClass("buttonLit");
		$("#flt_year").addClass("filterLit");
    }
	bs = getParameterByName('budgetSource');
	if (bs != null && bs != "") {
//		$("#budgetSource").addClass("buttonLit");
		$("#flt_budget").addClass("filterLit");
	}
	state = getParameterByName('state');
	if (state != null && state != "" && state != "0") {
		$("#filterState").addClass("buttonLit");
		$("#flt_state").addClass("filterLit");
	}
	replacementState = getParameterByName('replacementState');
	if (replacementState != null && replacementState != "" && replacementState != "0") {
		$("#filterReplacementState").addClass("buttonLit");
		$("#flt_replacement").addClass("filterLit");
	}
	if (getParameterByName('deviceName')) {
//		$("#deviceName").addClass("buttonLit");
		$("#flt_name").addClass("filterLit");
	}
	if (getParameterByName('deviceModel')) {
//		$("#deviceModel").addClass("buttonLit");
		$("#flt_model").addClass("filterLit");
	}
    if (getParameterByName('deviceNew')) {
        $("#flt_new").addClass("filterLit");
    }
	fp = getParameterByName('filterPlanner')
	if (fp != "2" && fp != "" && fp != null) {
//		$("#filterPlanner").addClass("buttonLit");
		$("#flt_planner").addClass("filterLit");
	}
	st = getParameterByName('site');	
	if (st != null && st != "" && st != 0) {
//		$("#filterSite").addClass("buttonLit");
		$("#flt_location").addClass("filterLit");
	}
	rt = getParameterByName('region');
	if (rt != null && rt != "" && rt != 0) {
//		$("#filterRegion").addClass("buttonLit");
		$("#flt_region").addClass("filterLit");
	}
	cap = getParameterByName('capital');
	if (cap != null && cap != "") {
		$("#flt_capital").addClass("filterLit");
	}
	dbs = getParameterByName('dbSource');
	if (dbs != null && dbs != "") {
		$("#flt_dbsource").addClass("filterLit");
	}
	ipa = getParameterByName('ipaddress');
	if (ipa != null && ipa != "") {
		$("#flt_ipaddress").addClass("filterLit");
	}
	maca = getParameterByName('macaddress');
	if (maca != null && maca != "") {
		$("#flt_macaddress").addClass("filterLit");
	}
	eosale = getParameterByName('end_of_sale');
	if (eosale != null && eosale != "") {
		$("#flt_end_of_sale").addClass("filterLit");
	}
	eosupport = getParameterByName('end_of_support');
	if (eosupport != null && eosupport != "") {
		$("#flt_end_of_support").addClass("filterLit");
	}
	ot = getParameterByName('olderThan');
	if (ot != null && ot != "" && ot != 0) {
//		$("#filterOld").addClass("buttonLit");
		$("#flt_lastseen").addClass("filterLit");
	}
	sn = getParameterByName('snFilter');
	if (sn != null && sn != "") {
		$("#flt_serial").addClass("filterLit");
	}
	vv = getParameterByName('version');
	if (vv != null && vv != "") {
		$("#flt_version").addClass("filterLit");
	}
    if (getParameterByName('direction')=="1") {
        $("#"+getParameterByName('orderBy')).addClass("up-arrow");
	} else {
        $("#"+getParameterByName('orderBy')).addClass("down-arrow");
    }

	pnt = getParameterByName('parent');
	if (pnt != null && pnt!= "" && pnt !=0) {
		$("#filterParent").addClass("buttonLit");
	}

	$("#page_start_"+getParameterByName('start')).addClass("pageLit");
});

$("#deviceNameInput deviceName a").on("click", function() {
    return false;
});

$("#deviceModelInput deviceModel a").on("click", function() {
	    return false;
});

$(":input").on('keyup', function (e) {
    if (e.key === 'Enter' || e.keyCode === 13) {
       alert(document.getElementById("deviceName").href);
    } else {
		alert("something");
	}
});
