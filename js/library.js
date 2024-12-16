function getParameterByName(name, url = window.location.href) {
    name = name.replace(/[\[\]]/g, '\\$&');
    var regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)'),
        results = regex.exec(url);
    if (!results) return null;
    if (!results[2]) return '';
    return decodeURIComponent(results[2].replace(/\+/g, ' '));
}

function jsReplaceQueryString(qs, param) {
	document.location.href= "?"+qs+document.getElementById(param).value;
}

function jsReplaceQueryStringValue (qs, param, value) {
	document.location.href = "?"+qs+"&"+param+"="+value
}

function jsClearQueryString (qs) {
	document.location.href = "?"+qs
}

function goToURL (url) {
	document.location.href = url;
}

function post(path, parameters) {
    var form = $('<form></form>');

    form.attr("method", "post");
    form.attr("action", path);

    $.each(parameters, function(key, value) {
        var field = $('<input></input>');

        field.attr("type", "hidden");
        field.attr("name", key);
        field.attr("value", value);

        form.append(field);
    });

    // The form needs to be a part of the document in
    // order for us to be able to submit it.
    $(document.body).append(form);
    form.submit();
}

function moveBudget(qs="") {
    var table = document.getElementById("samurai_table");
    var newBudget = document.getElementById("moveBudgetInput").value;
    var records=[];
    for (let i in table.rows){
        let row=table.rows[i];
        let cells=row.cells;
        if (i > 0 && i < table.rows.length) {
            if (cells[1].children[0].checked) {
                record = JSON.stringify({"id":cells[1].children[0].value,"newBudget":newBudget});
                records.push(record);
            }
        }
    }
    var params = {"records":records};
    post("/samurai/changeBudget?"+qs, params);
}

function moveSite(qs="") {
    var table = document.getElementById("samurai_table");
    var newSite = document.getElementById("moveSiteInput").value;
    var records=[];
    for (let i in table.rows){
        let row=table.rows[i];
        let cells=row.cells;
        if (i > 0 && i < table.rows.length) {
            if (cells[1].children[0].checked) {
                record = JSON.stringify({"id":cells[1].children[0].value,"newSite":newSite});
                records.push(record);
            }
        }
    }
    var params = {"records":records};
    post("/samurai/changeSite?"+qs, params);
}

function moveYear(qs="") {
	var table = document.getElementById("samurai_table");
	var newYear = document.getElementById("moveYearInput").value;
	var records=[];
	for (let i in table.rows){
		let row=table.rows[i];
		let cells=row.cells;
		if (i > 0 && i < table.rows.length) {
			if (cells[1].children[0].checked) { 
				record = JSON.stringify({"id":cells[1].children[0].value,"newYear":newYear});
				records.push(record);
			}
		}
	}
	var params = {"records":records};
	post("/samurai/changeYear?"+qs, params);
}

function movePlanner(qs="") {
    var table = document.getElementById("samurai_table");
    var newPlanner = document.getElementById("movePlannerInput").value;
    var records=[];
    for (let i in table.rows){
        let row=table.rows[i];
        let cells=row.cells;
        if (i > 0 && i < table.rows.length) {
            if (cells[1].children[0].checked) {
                record = JSON.stringify({"id":cells[1].children[0].value,"newPlanner":newPlanner});
                records.push(record);
            }
        }
    }
    var params = {"records":records};
    post("/samurai/changePlanner?"+qs, params);
}

function retireAssets(qs="") {
    var table = document.getElementById("samurai_table");
    var newPlanner = document.getElementById("movePlannerInput").value;
    var records=[];
    for (let i in table.rows){
        let row=table.rows[i];
        let cells=row.cells;
        if (i > 0 && i < table.rows.length) {
            if (cells[1].children[0].checked) {
                record = JSON.stringify({"id":cells[1].children[0].value,"retire":"True"});
                records.push(record);
            }
        }
    }
    var params = {"records":records};
    post("/samurai/retireAssets?"+qs, params);
}

function newReplacement(qs="") {
    var table = document.getElementById("samurai_table");
    var newReplacement = document.getElementById("newReplacementInput").value;
    var records=[];
    for (let i in table.rows){
        let row=table.rows[i];
        let cells=row.cells;
        if (i > 0 && i < table.rows.length) {
            if (cells[1].children[0].checked) {
                record = JSON.stringify({"id":cells[1].children[0].value,"newReplacement":newReplacement});
                records.push(record);
            }
        }
    }
    var params = {"records":records};
    post("/samurai/newReplacement?"+qs, params);
}

function newCapital(qs="") {
    var table = document.getElementById("samurai_table");
    var newCapital = document.getElementById("newCapitalInput").value;
    var records=[];
    for (let i in table.rows){
        let row=table.rows[i];
        let cells=row.cells;
        if (i > 0 && i < table.rows.length) {
            if (cells[1].children[0].checked) {
                record = JSON.stringify({"id":cells[1].children[0].value,"newCapital":newCapital});
                records.push(record);
            }
        }
    }
    var params = {"records":records};
    post("/samurai/newCapital?"+qs, params);
}

/*function fnExcelReport() {
    var tab_text="<table border='2px'><tr bgcolor='#87AFC6'>";
    var textRange; var j=0;
    tab = document.getElementById('samurai_table'); // id of table

    for(j = 0 ; j < tab.rows.length ; j++) 
    {     
        tab_text=tab_text+tab.rows[j].innerHTML+"</tr>";
        //tab_text=tab_text+"</tr>";
    }

    tab_text=tab_text+"</table>";
    tab_text= tab_text.replace(/<A[^>]*>|<\/A>/g, "");//remove if u want links in your table
    tab_text= tab_text.replace(/<img[^>]*>/gi,""); // remove if u want images in your table
    tab_text= tab_text.replace(/<input[^>]*>|<\/input>/gi, ""); // reomves input params

    var ua = window.navigator.userAgent;
    var msie = ua.indexOf("MSIE "); 

    if (msie > 0 || !!navigator.userAgent.match(/Trident.*rv\:11\./))      // If Internet Explorer
    {
        txtArea1.document.open("txt/html","replace");
        txtArea1.document.write(tab_text);
        txtArea1.document.close();
        txtArea1.focus(); 
        sa=txtArea1.document.execCommand("SaveAs",true,"samurai.xlsx");
    }  
    else                 //other browser not tested on IE 11
        sa = window.open('data:application/vnd.ms-excel,' + encodeURIComponent(tab_text),'_blank','noopener,noreferrer');  

    return (sa);
}*/

var MyBlobBuilder = function() {
  this.parts = [];
}

MyBlobBuilder.prototype.append = function(part) {
  this.parts.push(part);
  this.blob = undefined; // Invalidate the blob
};

MyBlobBuilder.prototype.getBlob = function() {
  if (!this.blob) {
    this.blob = new Blob(this.parts, { type: "application/vnd.ms-excel" });
  }
  return this.blob;
};

function fnExcelReport() {
    var myBlobBuilder = new MyBlobBuilder();
	myBlobBuilder.append("<table border='2px'><tr bgcolor='#87AFC6'>");
	var textRange; var j=0;
    tab = document.getElementById('samurai_table'); // id of table

    for(j = 0 ; j < tab.rows.length ; j++)
    {
		data = tab.rows[j].innerHTML+"</tr>";
		data =data.replace(/<A[^>]*>|<\/A>/g, "");
		data =data.replace(/<img[^>]*>/gi,"");
		data =data.replace(/<input[^>]*>|<\/input>/gi, "");
        myBlobBuilder.append(data);
    }

    myBlobBuilder.append("</table>");

	var myBlob = myBlobBuilder.getBlob()
    // Blob ([document.getElementById('samurai_table').innerHTML], {type:'application/vnd.ms-excel'});
	var url = window.URL.createObjectURL(myBlob);
	var a=document.createElement("a");
	document.body.appendChild(a);
	a.href = url;
	a.download = "samurai.xls";
	a.click();
}

function exportExcel() {
	doc = window.open(document.URL+"&exportToExcel=1&page=9999999","_blank","opener,location=yes,height=300,width=400,scrollbars=no,status=no");
}
