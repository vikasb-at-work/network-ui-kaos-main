		am4core.ready(function() {

		// Themes begin
		am4core.useTheme(am4themes_animated);
		// Themes end

		// Create map instance
		var chart = am4core.create("chart_div", am4maps.MapChart);

		// Set map definition
		chart.geodata = am4geodata_worldLow;

		// Set projection
		chart.projection = new am4maps.projections.Miller();

		// Series for World map
		var worldSeries = chart.series.push(new am4maps.MapPolygonSeries());
		worldSeries.exclude = ["AQ"];
		worldSeries.useGeodata = true;

		var polygonTemplate = worldSeries.mapPolygons.template;
		polygonTemplate.tooltipText = "{name}";
		polygonTemplate.fill = chart.colors.getIndex(0);
		polygonTemplate.nonScalingStroke = true;

		// Hover state
		var hs = polygonTemplate.states.create("hover");
		hs.properties.fill = am4core.color("orange");

		// Series for United States map
		var usaSeries = chart.series.push(new am4maps.MapPolygonSeries());
		usaSeries.geodata = am4geodata_usaLow;

		var usPolygonTemplate = usaSeries.mapPolygons.template;
		usPolygonTemplate.tooltipText = "{name}";
		usPolygonTemplate.fill = chart.colors.getIndex(1);
		usPolygonTemplate.nonScalingStroke = true;

		// Hover state
		var hs = usPolygonTemplate .states.create("hover");
		hs.properties.fill = am4core.color("orange");

		var imageSeries = chart.series.push(new am4maps.MapImageSeries());
	
		var imageSeriesTemplate = imageSeries.mapImages.template;
		var circle = imageSeriesTemplate.createChild(am4core.Circle);
		circle.radius=3;
		circle.fill = am4core.color("orange");
		circle.stroke = am4core.color("white");
		circle.strokeWidth = .5;
		circle.nonScaling = false;
		circle.tooltipText = "{title}";

		imageSeriesTemplate.propertyFields.latitude = 'latitude';
		imageSeriesTemplate.propertyFields.longitude = 'longitude';

		imageSeries.data = [];
		
		var item=[];

		var i=0; x=-1;

        const loadData = async () => {
			const response = await fetch("/rest/v1/gmi-sites-geo");
			const result = await response.json();
			var imgSeriesObj = [];
			for (var row of result["result"]){
				item.push( {"latitude" : row.lat, "longitude" : row.lng, "title" : row.site} );
				x++;
			};
			imageSeries.data = item;
		
		};

		loadData();
		imageSeries.data = item;


	console.log (item);
	
	chart.series.push(imageSeries);


		imageSeriesTemplate.events.on("hit", function(ev) {
				ev.target.series.chart.zoomToMapObject(ev.target);
				//console.log("Clicked on " + ev.target.dataItem.dataContext.title);
				if (ev.target.dataItem.dataContext.title == "Minneapolis") { window.location.href = '/control?Location=MGO'; } else 
				{ window.location.href = '/control?Location='+ev.target.dataItem.dataContext.title; }
			});

});
