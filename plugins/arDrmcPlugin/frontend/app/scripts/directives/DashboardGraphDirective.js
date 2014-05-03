'use strict';

var myd3 = require('d3');
var myrickshaw = require('rickshaw');

module.exports = function () {
  return {
    restrict: 'E',
    scope: {
    },
    template: '<rs-y-axis></rs-y-axis><rs-chart></rs-chart><rs-x-axis></rs-x-axis><rs-legend></rs-legend>',
    link: function (scope, element, attrs) {
      var dataset = angular.fromJson(attrs.chartData);

      if (attrs.type === 'pie') {

        // ---------------------------
        // from storage codec directive
        // ---------------------------

        var w = attrs.width,
          h = attrs.width,
          r = w / 2 * 0.8,
          //inner =  w * 0.1,
          color = myd3.scale.category20c();

        var svg = myd3.select(element[0])
          .append('svg:svg')
          .data([dataset])
          .style ('stroke', 'white')
          .attr('width', w)
          .attr('height', h)
          .append('svg:g')
          .attr('transform', 'translate(' + r * 1.1 + ',' + r * 1.1 + ')');

        var arc = myd3.svg.arc()
          //.innerRadius(inner)
          .outerRadius(r);

        var pie = myd3.layout.pie()
          .value(function (d) { return d.value; });

        var arcs = svg.selectAll('g.slice')
          .data(pie)
          .enter()
          .append('svg:g')
          .attr('class', 'slice');

        arcs.append('svg:path')
            .attr('fill', function (d, i) { return color(i);})
            .attr('d', arc);


        var label_width = Number.MIN_VALUE;

        for (var i = 0; i < dataset.length; i++) {
          label_width = Math.max(label_width, dataset[i].label.length);
        }
        // round up to 10th
        label_width = label_width * 8;
        var label_height = dataset.length * 20;

        var legend = myd3.select(element[0]).append('svg')
          .attr('class', 'legend')
          .attr('width', label_width)
          .attr('height', label_height)
          .selectAll('g')
          .data(color.domain().slice().reverse())
          .enter().append('g')
          .attr('transform', function (d, i) { return 'translate(0,' + i * 20 + ')';});

        legend.append('rect')
          .attr('width', 18)
          .attr('height', 18)
          .style('fill', color);

        legend.append('text')
          .attr('x', 24)
          .attr('y', 9)
          .attr('dy', '.35em')
          .text(function (d) {
            var label = dataset[d].label;
            return label;
          });
      } else if (attrs.type === 'line') {

        // ---------------------------
        // from line chart directive
        // ---------------------------

        var palette = new myrickshaw.Color.Palette();
        var max = Number.MIN_VALUE;
        console.log('dataset', dataset);
        for (var y = 0; y < dataset.length; y++
          ) {
          dataset[y].color = palette.color();
          for (var j = 0; j < dataset[y].data.length; j++) {
            max = Math.max(max, dataset[y].data[j].y);
          }
        }
        // round up to 10th
        max = Math.ceil(max / 10) * 10;

        var graph = new myrickshaw.Graph({
          element: element.find('rs-chart')[0],
          width: attrs.width,
          height: attrs.height,
          series: dataset,
          max: max
        });

        var xAxis = new myrickshaw.Graph.Axis.X({
          graph: graph,
          element: element.find('rs-x-axis')[0],
          orientation: 'bottom',
          pixelsPerTick: attrs.xperTick
        });
        xAxis.render();

        var yAxis = new myrickshaw.Graph.Axis.Y({
          graph: graph,
          element: element.find('rs-y-axis')[0],
          pixelsPerTick: attrs.yperTick,
          orientation: 'left',
          tickFormat: myrickshaw.Fixtures.Number.formatKMBT
        });
        yAxis.render();

        var lineLegend = new myrickshaw.Graph.Legend({
          graph: graph,
          element: element.find('rs-legend')[0]
        });
        lineLegend.render();

        graph.setRenderer('line');
        graph.render();

      } else {
        return;
      }
    }
  };
};
