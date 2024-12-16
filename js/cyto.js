			window.addEventListener('DOMContentLoaded', function(){

/*				$('.hover_bkgr_fricc').click(function(){
						$('.hover_bkgr_fricc').hide();
				});
*/
				$('.popupCloseButton').click(function(){
						$('.hover_bkgr_fricc').hide();
				});
				var cy = window.cy = cytoscape({
					container: document.getElementById('cy'),

					ready: function(){
					},

					style: [
						{
							selector: 'node',
							css: {
								'height': 80,
								'width': 80,
								'background-fit': 'cover',
								'border-color': '#A9A9A9',
								'border-width': 5,
								'border-opacity': 1,
								'content': 'data(name)',
							}
						},
						{
							selector: 'edge',
							css: {
								'curve-style': 'unbundled-bezier',
								'target-arrow-shape': 'circle',
								'source-arrow-shape': 'circle'
							}
						},
						{
							selector: '[name="MGO"]',
							css: { 
								'border-color': '#0000FF'
							}
						},
						{
							selector: '[nodetype="site"]',
							css: {
								'background-image': '/images/site.png'
							}
						},
						{
							selector: '[nodetype="Site"]',
							css: {
								'background-image': '/images/site.png'
							}
						},
						{
							selector: '[nodetype="Router"]',
							css: {
								'background-image': '/images/router.png'
							}
						},
						{
							selector: '[nodetype="Switch"]',
							css: {
								'shape': 'square',
								'height': 60,
								'width': 80,
								'background-image': '/images/nexus.png',
								'background-size': 'cover',
								'background-position': 'center center',
								'background-repeat': 'no-repeat'
							}
						},
						{
							selector: '[nodetype="l2switch"]',
							css: {
								'shape': 'square',
								'background-image': '/images/l2switch.png'
							}
						},
						{
							selector: '[nodetype="l3switch"]',
							css: {
								'shape': 'square',
								'background-image': '/images/l3switch.png'
							}
						},
						{
							selector: '[nodetype="cloud"]',
							css: {
								'height': 138,
								'width': 288,
								'border-opacity': 0,
								'border-color': '#FFFFFF',
								'border-width': 0,
								'background-image': '/images/cloud.png',
								'shape': 'hexagon',
								'color': 'blue',
								'text-margin-y': 90

							}
						},

						{
							selector: '[lastupdate^="-"]',
							css: {
								'border-color': '#FF8C00'
							}
						},
						{
							selector: '[lastupdate^="0"]',
							css: {
								'border-color': '#32CD32'
							}
						},
						{
							selector: '[lastupdate^="1"]',
							css: {
								'border-color': '#FF0000'
							}
						},
						{
							selector: '[lastupdate^="2"]',
							css: {
								'border-color': '#FF0000'
							}
						},
						{
							selector: '[lastupdate^="3"]',
							css: {
								'border-color': '#FF0000'
							}
						},
						{
							selector: '[lastupdate^="4"]',
							css: {
								'border-color': '#FF0000'
							}
						},
						{
							selector: '[lastupdate^="5"]',
							css: {
								'border-color': '#FF0000'
							}
						},
						{
							selector: '[lastupdate^="6"]',
							css: {
								'border-color': '#FF0000'
							}
						},
						{
							selector: '[lastupdate^="7"]',
							css: {
								'border-color': '#FF0000'
							}
						},
						{
							selector: '[lastupdate^="8"]',
							css: {
								'border-color': '#FF0000'
							}
						},
						{
							selector: '[lastupdate^="9"]',
							css: {
								'border-color': '#FF0000'
							}
						},
						{
							selector: '[lastupdate="11"]',
							css: {
								'border-color': '#32CD32'
							}
						},
						{
							selector: '[lastupdate="12"]',
							css: {
								'border-color': '#32CD32'
							}
						},
						{
							selector: '[lastupdate="13"]',
							css: {
								'border-color': '#32CD32'
							}
						},
						{
							selector: '[lastupdate="14"]',
							css: {
								'border-color': '#32CD32'
							}
						},
						{
							selector: '[lastupdate="15"]',
							css: {
								'border-color': '#32CD32'
							}
						},
						{
							selector: '[lastupdate="16"]',
							css: {
								'border-color': '#32CD32'
							}
						},
						{
							selector: '[lastupdate="17"]',
							css: {
								'border-color': '#32CD32'
							}
						},
						{
							selector: '[lastupdate="18"]',
							css: {
								'border-color': '#32CD32'
							}
						},
						{
							selector: '[lastupdate="19"]',
							css: {
								'border-color': '#32CD32'
							}
						},
						{
							selector: '[lastupdate="20"]',
							css: {
								'border-color': '#32CD32'
							}
						},
						{
							selector: '[lastupdate="21"]',
							css: {
								'border-color': '#32CD32'
							}
						},
						{
							selector: '[lastupdate="22"]',
							css: {
								'border-color': '#32CD32'
							}
						},
						{
							selector: '[lastupdate="23"]',
							css: {
								'border-color': '#32CD32'
							}
						},
						{
							selector: '[lastupdate="24"]',
							css: {
								'border-color': '#32CD32'
							}
						},
						{
							selector: '[lastupdate="25"]',
							css: {
								'border-color': '#32CD32'
							}
						},
						{
							selector: '[lastupdate="26"]',
							css: {
								'border-color': '#32CD32'
							}
						},
						{
							selector: '[lastupdate="27"]',
							css: {
								'border-color': '#32CD32'
							}
						},
						{
							selector: '[lastupdate="28"]',
							css: {
								'border-color': '#32CD32'
							}
						},
						{
							selector: '[lastupdate="29"]',
							css: {
								'border-color': '#32CD32'
							}
						},
						{
							selector: '[lastupdate="30"]',
							css: {
								'border-color': '#32CD32'
							}
						},
						{
							selector: 'node:active',
							css: {
								'border-color': '#0000FF'
							}
						},
						{
							selector: '.eh-handle',
						        style: {
					                	'background-color': 'red',
					        	        'width': 12,
						                'height': 12,
						                'shape': 'ellipse',
						                'overlay-opacity': 0,
						                'border-width': 12, // makes the handle easier to hit
						                'border-opacity': 0
						              }
						},

            {
              selector: '.eh-hover',
              style: {
                'background-color': 'red'
              }
            },

            {
              selector: '.eh-source',
              style: {
                'border-width': 2,
                'border-color': 'red'
              }
            },

            {
              selector: '.eh-target',
              style: {
                'border-width': 2,
                'border-color': 'red'
              }
            },

            {
              selector: '.eh-preview, .eh-ghost-edge',
              style: {
                'background-color': 'red',
                'line-color': 'red',
                'target-arrow-color': 'red',
                'source-arrow-color': 'red'
              }
            },

            {
              selector: '.eh-ghost-edge.eh-preview-active',
              style: {
                'opacity': 0
              }
            }

					],

					elements: {
						nodes: [
							//{ data: { id: 'MGO', name: 'MGO', nodetype: 'site' } },
							//{ data: { id: 'JFB', name: 'JFB', nodetype: 'site' } },
							//{ data: { id: 'Minneapolis', name: 'Minneapolis', nodetype: 'city' } },
							//{ data: { id: 'Chanhassen', name: 'Chanhassen', nodetype: 'site' } },
							//{ data: { id: 'MGOR1', name: 'MGOR1', nodetype: 'router', lastupdate: '01' } },
							//{ data: { id: 'JFBR1', name: 'JFBR1', nodetype: 'router', lastupdate: '01' } },
							//{ data: { id: 'MGOR2', name: 'MGOR2', nodetype: 'router', lastupdate: '31' } },
							//{ data: { id: 'MGOR3', name: 'MGOR3', nodetype: 'router', lastupdate: '30' } },
							//{ data: { id: 'CL3', name: 'CL3', nodetype: 'cloud' } },
							//{ data: { id: 'VZ', name: 'VZ', nodetype: 'cloud' } },
							//{ data: { id: 'INTERNET', name: 'INTERNET', nodetype: 'cloud' } }
						],
						edges: [
							//{ data: { source: 'Minneapolis', target: 'MGO' } },
							//{ data: { source: 'Minneapolis', target: 'JFB' } },
							//{ data: { source: 'Minneapolis', target: 'Chanhassen' } },
							//{ data: { source: 'MGOR1', target: 'MGO' } },
							//{ data: { source: 'JFBR1', target: 'JFB' } },
							//{ data: { source: 'MGOR2', target: 'MGO' } },
							//{ data: { source: 'MGOR3', target: 'MGO' } },
							//{ data: { source: 'MGOR1', target: 'CL3' } }
						
						]
					},

				  layout: {
						 	name: 'cose',
							idealEdgeLength: 100,
							nodeOverlap: 20,
							refresh: 20,
							fit: true,
							padding: 30,
							randomize: false,
							componentSpacing: 100,
							nodeRepulsion: 400000,
							edgeElasticity: 100,
							nestingFactor: 5,
							gravity: 80,
							numIter: 1000,
							initialTemp: 200,
							coolingFactor: 0.95,
							minTemp: 1.0
						}
				});




				cy.cxtmenu({
					selector: '[nodetype="Site"]',

					commands: [
						{
							content: '<span class="fa fa-flash fa-2x"></span>',
							select: function(ele){
								console.log( ele.id() );
							}
						},

						{
							content: '<span class="fa fa-star fa-2x"></span>',
							select: function(ele){
								console.log( ele.data('name') );
							},
							enabled: false
						},

						{
							content: 'Routers',
							select: function(ele){
								console.log( ele.position() );
								alert("You picked routers");
							}
						},

						{
							content: 'Switches',
							select: function(ele){
								console.log( ele.position());
								alert("You picked switches");
							}
						},
						{
							content: '+ Router',
							select: function(ele){
								console.log( 'add new router' );
								var name = askQuestion('Please enter a router name');
								console.log(name);
								console.log(event.clientX)
								console.log(ele.data('name'))
								cy.add([
									{
										group: 'nodes',
										data: { id: name, name: name, nodetype: 'Router', lastupdate: '-1' },
										position: { x: event.clientX-1, y: event.clientY-1 }
									},
									{
										group: 'edges',
										data: { source: ele.data('name'), target: name }
									}
								]);	
                                var layout = cy.layout({name: 'cose'});
                                layout.run();
							}
						},
						{
							content: '+ L2 Switch',
							select: function(ele){
								console.log( 'add new L2 switch' );
								var name = askQuestion('Please enter a switch name');
								console.log(name);
								console.log(event.clientX)
								console.log(ele.data('name'))
								cy.add([
									{
										group: 'nodes',
										data: { id: name, name: name, nodetype: 'l2switch', lastupdate: '-1' },
										position: { x: event.clientX-1, y: event.clientY-1 }
									},
									{
										group: 'edges',
										data: { source: ele.data('name'), target: name }
									}
								]);
								var layout = cy.layout({name: 'cose'});
								layout.run();	
							}
						},
						{
							content: '+ L3 Switch',
							select: function(ele){
								console.log( 'add new L2 switch' );
								var name = askQuestion('Please enter a switch name');
								console.log(name);
								console.log(event.clientX)
								console.log(ele.data('name'))
								cy.add([
									{
										group: 'nodes',
										data: { id: name, name: name, nodetype: 'l3switch', lastupdate: '-1' },
										position: { x: event.clientX-1, y: event.clientY-1 }
									},
									{
										group: 'edges',
										data: { source: ele.data('name'), target: name }
									}
								]);
								var layout = cy.layout({name: 'cose'});
								layout.run();	
							}
						}
					]
				});
				
				cy.cxtmenu({
					selector: '[nodetype="Router"]',

					commands: [
                        {
                            content: '<span class="fa fa-user-ninja fa-2x"></span><BR><span>Samurai</span>',
                            select: function(ele){
                                console.log( ele.id() );
								samurai_get_years().then(function(response) {
									samurai_year('MGOR1',"Year 1").then(function(response2) {
										content = "<ul id='popUpList'>\n";
										for (const item of response.years) {
											content = content + "<li class=popUpItem><a href='javascript:samurai_set_year(" + '"' + 'MGOR1'+'"'+','+'"'+item+'"'+");'><span>";
											if (response2.year == item) { content = content + "<i class='fa fa-check'></i> "; }
											content = content + item + "</span></a></li>\n";
										}
										content = content + "</ol>";
										popup(content);
									});
								});
                            }
                        },
						{
							content: '<span class="fa fa-file-upload fa-2x"></span><BR><span>QoS</span>',
							select: function(ele){
								console.log( ele.id() );
							}
						},

						{
							content: '<span class="fa fa-star fa-2x"></span>',
							select: function(ele){
								console.log( ele.data('name') );
							},
							enabled: false
						},
						{
							content: 'connect',
							select: function(ele) {
        							var eh = cy.edgehandles();
								eh.start( cy.$('node:selected') );
							}
						}
					]
				});

				cy.cxtmenu({
					selector: '[nodetype="l2switch"]',

					commands: [
						{
							content: '<span class="fa fa-flash fa-2x"></span>',
							select: function(ele){
								console.log( ele.id() );
							}
						},

						{
							content: '<span class="fa fa-star fa-2x"></span>',
							select: function(ele){
								console.log( ele.data('name') );
							},
							enabled: false
						}
					]
				});

				cy.cxtmenu({
					selector: '[nodetype="l3switch"]',

					commands: [
						{
							content: '<span class="fa fa-flash fa-2x"></span>',
							select: function(ele){
								console.log( ele.id() );
							}
						},

						{
							content: '<span class="fa fa-star fa-2x"></span>',
							select: function(ele){
								console.log( ele.data('name') );
							},
							enabled: false
						}
					]
				});

				cy.cxtmenu({
					selector: 'edge',

					commands: [
					]
				});

				cy.cxtmenu({
					selector: 'core',

					commands: [
						{
							content: '<span class="fa fa-home fa-2x"></span>',
							select: function(){
								window.location.href = "/";
							}
						},

						{
							content: '<span class="fa fa-angle-double-left fa-2x"></span>',
							select: function(){
								console.log(queryBefore);
								cy.elements().remove();
								getData(queryBefore);
							}
						},

						{
								content: '<span class="fa fa-plus fa-2x"></span>',
								select: function(ele){
								console.log( 'add new site' );
								var name = askQuestion('Please enter a site name');
								console.log(name);
								console.log(ele.data('name'));
								console.log(event.clientX)
								console.log(event.cyTarget)
								cy.add([
									{
										group: 'nodes',
										data: { id: name, name: name, nodetype: 'site' },
										position: { x: event.clientX, y: event.clientY }
									}
								]);
								var layout = cy.layout({name: 'cose'});
					            layout.run();
							}
						}
					]
				});

        var tappedBefore = null;
        var tappedTimeout;
        cy.on('tap', function(event) {
          var tappedNow = event.cyTarget;
           if (tappedTimeout && tappedBefore) {
            clearTimeout(tappedTimeout);
         }
          if(tappedBefore === tappedNow) {
            this.trigger('doubleTap', event);
            tappedBefore = null;
            originalTapEvent = null;
          } else {
              tappedTimeout = setTimeout(function(){ tappedBefore = null; orignalTapEvent = null; }, 300);
             tappedBefore = tappedNow;
             originalTapEvent = event;
			 console.log (event.target._private.data["name"]);
          }
        });

        cy.on('doubleTap', function(event, originalTapEvent) {
          event = originalTapEvent;
          var tappedNow = event;
            console.log ("Double-clicked: " + event.target._private.data["name"]);
			cy.elements().remove();
			var query= "MATCH (s:Site)-[:DEVICE_IN]-(OtherNodes) where s.name='"+event.target._private.data["name"]+"' RETURN s, OtherNodes";
			getData(query, event.target._private.data["name"]);
        });

			});

		var lastQuery=null;
		var queryBefore=null;

		function getData(query="MATCH (n:Site) RETURN n", source=null) {
			queryBefore = lastQuery;
			lastQuery = query;
			var authToken = neo4j.v1.auth.basic('neo4j', 'network');
		    console.log(authToken);
		    var driver = neo4j.v1.driver('bolt://172.25.202.61:7687', authToken, {encrypted: false});
	        var session = driver.session();

			var statement = query;;
			parameters = {};
			session.run(statement, parameters).subscribe({
				onBegin: function(stuff) {
					console.log("Function initialized");
				},
				onNext: function(record) {
			            record.forEach(function(value) {
							//console.log(value);
							//console.log("Labels: "+value.labels[0]);
							//console.log("Name:" + value.properties["name"]);
							//console.log("Source: "+source);
							if (source != null && source != value.properties["name"] && value.properties["name"] != null) {
								cy.add([
									{
										group: 'nodes',
										data: { nodetype: value.labels[0], name: value.properties["name"], id: value.properties["name"], x: 100, y: 100 }
									},
									{
										group: 'edges',
										data: { source: source, target: value.properties["name"]}
									}
									]);
							} else
							{
								cy.add([
                                	{
                                    	group: 'nodes',
	                                    data: { nodetype: value.labels[0], name: value.properties["name"], id: value.properties["name"], x: 100, y: 100 }
    	                            }
								]);
							}
						})
		        	  },
			onCompleted: function(metadata) {
				var layout = cy.layout({name: 'cose'});
				layout.run();
			}
		})
		}
	
		var urlParams = new URLSearchParams(window.location.search);
		if (urlParams.get('Location') == 'MGO') { 
			getData("MATCH (s:Site)-[:DEVICE_IN]-(OtherNodes) where s.name='MGO' RETURN s, OtherNodes", "MGO"); 
			getData("MATCH (s:Site)-[:DEVICE_IN]-(OtherNodes) where s.name='JFB' RETURN s, OtherNodes", "JFB"); 
		} else {
			query = "MATCH (s:Site)-[:DEVICE_IN]-(OtherNodes) where s.name='"+urlParams.get('Location')+"' RETURN s, OtherNodes";
			console.log(query);
			getData(query, urlParams.get('Location'));
		}

