function samurai_set_year(item, year) {
	samurai_year(item, year).then (
			function(response) {
				popup_close(); 
			}
	);
}
