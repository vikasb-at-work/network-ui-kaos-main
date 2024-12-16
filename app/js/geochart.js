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

        function loadData(query="MATCH (n:Site) RETURN n", source=null) {
            var authToken = neo4j.v1.auth.basic('neo4j', 'network');
             //console.log(authToken);
            var driver = neo4j.v1.driver('bolt://172.25.202.61:7687', authToken, {encrypted: false});
            var session = driver.session();
			var imgSeriesObj = []; 
            var statement = query;;
            parameters = {};
            session.run(statement, parameters).subscribe({
                onBegin: function(stuff) {
                    //console.log("Function initialized");
                },
                onNext: function(record) {
                        record.forEach(
							function(value) {
                            	//console.log(value);
	                            //console.log("Labels: "+value.labels[0]);
    	                        //console.log("Name:" + value.properties["name"]);
        	                    //console.log("Source: "+source);
								//
								if (value.properties["lat"] && value.properties["lng"]) {
									item.push(
									{"latitude" : parseFloat(value.properties["lat"]), 
									"longitude" : parseFloat(value.properties["lng"]), 
									"title" : value.properties["name"]
									});
									x++;
									//imgSeriesObj[x]= imageSeries.mapImages.create();
									//imgSeriesObj[x].latitude = parseFloat(value.properties["lat"]);
									//imgSeriesObj[x].longitude = parseFloat(value.properties["lng"]);
									//imgSeriesObj[x].id = value.properties["name"];
									//imgSeriesObj[x].title = value.properties["name"];
								}
							})
            		},
            	onCompleted: function(metadata) {
					imageSeries.data = item;
  //      for (i=0; i<x; i++) {
 //           imgSeriesObj[i] = imageSeries.mapImages.create();
 //           imgSeriesObj[i].latitude = item[i].latitude;
 //           imgSeriesObj[i].longitude = item[i].longitude;
 //           imgSeriesObj[i].title = item[i].title;
 //       }
//			console.log(imgSeriesObj[1]);
            		}	
        		})
			};
       

		loadData();
//		imageSeries.data = item;

//	imageSeries.data = [{
//			"latitude": 44.9778,
//			"longitude": -93.2650,
//			"title": "Minneapolis"
//		}];

	console.log (item);
	
//	chart.series.push(imageSeries);

//		console.log(imageSeries.data);

		imageSeriesTemplate.events.on("hit", function(ev) {
				ev.target.series.chart.zoomToMapObject(ev.target);
				//console.log("Clicked on " + ev.target.dataItem.dataContext.title);
				if (ev.target.dataItem.dataContext.title == "Minneapolis") { window.location.href = '/control?Location=MGO'; } else 
				{ window.location.href = '/control?Location='+ev.target.dataItem.dataContext.title; }
			});

});
