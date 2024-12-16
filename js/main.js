// photos from flickr with creative commons license

var cy = cytoscape({
  container: document.getElementById('cy'),

  boxSelectionEnabled: false,
  autounselectify: true,

  style: cytoscape.stylesheet()
    .selector('node')
      .css({
        'height': 80,
        'width': 80,
        'background-fit': 'cover',
        'border-color': '#000',
        'border-width': 0,
        'border-opacity': 0.5,
		'content': 'data(name)',
		'shape': 'hexagon',
      })
    .selector('.eating')
      .css({
        'border-color': 'red'
      })
    .selector('.eater')
      .css({
        'border-width': 9
      })
    .selector('edge')
      .css({
        'curve-style': 'bezier',
        'width': 6,
        'target-arrow-shape': 'triangle',
        'line-color': '#ffaaaa',
        'target-arrow-color': '#ffaaaa',
		'content': 'data(name)',
      })
    .selector('#spoke-source')
      .css({
        'background-image': 'http://vl-kaosdev01/images/vpc.jpg'
      })
    .selector('#spoke-dest')
      .css({
        'background-image': 'http://vl-kaosdev01/images/vpc.jpg'
      })
    .selector('#palo-prod-central-1')
      .css({
        'background-image': 'http://vl-kaosdev01/images/firewall.png'
      })
    .selector('#palo-prod-central-2')
      .css({
        'background-image': 'http://vl-kaosdev01/images/firewall.png'
      })
    .selector('#palo-nonprod-central-1')
      .css({
        'background-image': 'http://vl-kaosdev01/images/firewall.png'
      })
    .selector('#palo-nonprod-central-2')
      .css({
        'background-image': 'http://vl-kaosdev01/images/firewall.png'
      })
    .selector('#palo-nonprod-east-1')
      .css({
        'background-image': 'http://vl-kaosdev01/images/firewall.png'
      })
    .selector('#palo-nonprod-east-2')
      .css({
        'background-image': 'http://vl-kaosdev01/images/firewall.png'
      })
    .selector('#palo-prod-east-1')
      .css({
        'background-image': 'http://vl-kaosdev01/images/firewall.png'
      })
    .selector('#palo-prod-east-2')
      .css({
        'background-image': 'http://vl-kaosdev01/images/firewall.png'
      })
    .selector('#load-balancer-prod-central')
      .css({
        'background-image': 'http://vl-kaosdev01/images/load-balancer.png'
      })
    .selector('#load-balancer-nonprod-central')
      .css({
        'background-image': 'http://vl-kaosdev01/images/load-balancer.png'
      })
    .selector('#load-balancer-prod-east')
      .css({
        'background-image': 'http://vl-kaosdev01/images/load-balancer.png'
      })
    .selector('#load-balancer-nonprod-east')
      .css({
        'background-image': 'http://vl-kaosdev01/images/load-balancer.png'
      })
    .selector('#compute-prod-central')
      .css({
        'background-image': 'http://vl-kaosdev01/images/compute.png'
      })
  .selector('#compute-nonprod-central')
      .css({
        'background-image': 'http://vl-kaosdev01/images/compute.png'
      })
  .selector('#compute-prod-east')
      .css({
        'background-image': 'http://vl-kaosdev01/images/compute.png'
      })
  .selector('#compute-nonprod-east')
      .css({
        'background-image': 'http://vl-kaosdev01/images/compute.png'
      })
  .selector('#devhub')
      .css({
        'background-image': 'http://vl-kaosdev01/images/vpc.jpg'
      })
  .selector('#prodhub')
      .css({
        'background-image': 'http://vl-kaosdev01/images/vpc.jpg'
      }),

  elements: {
    nodes: [
      { data: { id: 'compute-prod-central', name: 'xjn5193' } },
      { data: { id: 'spoke-source', name: 'spoke-sap' } },
      { data: { id: 'load-balancer-prod-central', name: 'ilb-prod central' } },
      { data: { id: 'palo-prod-central-1', name: 'palofw-prod-central-1' } },
      { data: { id: 'palo-prod-central-2', name: 'palofw-prod-central-2' } },
      { data: { id: 'prodhub', name: 'gmi-prodhub' } },
      { data: { id: 'spoke-dest', name: 'spoke-bms' } },
      { data: { id: 'compute-prod-east', name: 'bms001' } }
    ],
    edges: [
      { data: { source: 'compute-prod-central', target: 'spoke-source', name: 'tag-central; subnet 10.2.1.1' } },
      { data: { source: 'spoke-source', target: 'load-balancer-prod-central', name: '0/0 tagged central' } },
      { data: { source: 'load-balancer-prod-central', target: 'palo-prod-central-1', name: 'backend-palofw-prod-central' } },
      { data: { source: 'load-balancer-prod-central', target: 'palo-prod-central-2', name: 'backend-palofw-prod-central' } },
      { data: { source: 'palo-prod-central-1', target: 'prodhub', name: 'tagged central; no-nat; next-hop prod-hub' } },
      { data: { source: 'palo-prod-central-2', target: 'prodhub', name: 'tagged central; no-nat; next-hop prod-hub' } },
      { data: { source: 'prodhub', target: 'spoke-dest', name: 'peered route to destination' } },
      { data: { source: 'spoke-dest', target: 'compute-prod-east', name: 'subnet 10.1.1.1' } }
    ]
  },

  layout: {
    name: 'breadthfirst',
    directed: true,
    padding: 10
  }

}); // cy init

cy.on('tap', 'node', function(){
  var nodes = this;
  var tapped = nodes;
  var food = [];

  nodes.addClass('eater');

  for(;;){
    var connectedEdges = nodes.connectedEdges(function(el){
      return !el.target().anySame( nodes );
    });

    var connectedNodes = connectedEdges.targets();

    Array.prototype.push.apply( food, connectedNodes );

    nodes = connectedNodes;

    if( nodes.empty() ){ break; }
  }

  var delay = 0;
  var duration = 500;
  for( var i = food.length - 1; i >= 0; i-- ){ (function(){
    var thisFood = food[i];
    var eater = thisFood.connectedEdges(function(el){
      return el.target().same(thisFood);
    }).source();

    thisFood.delay( delay, function(){
      eater.addClass('eating');
    } ).animate({
      position: eater.position(),
      css: {
        'width': 10,
        'height': 10,
        'border-width': 0,
        'opacity': 0
      }
    }, {
      duration: duration,
      complete: function(){
        thisFood.remove();
      }
    });

    delay += duration;
  })(); } // for

}); // on tap
