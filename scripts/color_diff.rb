#!/usr/bin/ruby -w
#
# Filter and modify a computation graph produced by the "diff" tool.
#
# This file is part of SHVAL. For details, see https://github.com/lam2mo/shval
# Please also see the LICENSE file for our notice and the LGPL.
#
# Original version written by Logan Moody.
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License (as published by the Free
# Software Foundation) version 2.1 dated February 1999.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the IMPLIED WARRANTY OF MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the terms and conditions of the GNU General
# Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

# a single differential trace computational graph node
require 'optparse'

$verbose = false;
$relative = false;
$collapse = false;
$graph = Hash.new

parser = OptionParser.new do|opts|
  opts.banner = "Usage: example.rb [options]"

  opts.on("-v", "--verbose", "Run verbosely") do
    $verbose = true
  end

  opts.on("-r", "--relative", "Use relative error instead of absolute") do
    $relative = true
  end

  opts.on("-c", "--collapse", "Collapse all functions to nodes") do
    $collapse = true
  end

  opts.on('-h', '--help', 'Displays Help') do
    puts opts
    exit
  end

end

parser.parse!

# format color
def colorf (color)
  "#{color.to_s(16).rjust(2, '0')}"
end

class DiffNode
  attr_reader :label, :abserr, :relerr, :addr, :disas, :func, :src
  attr_accessor :in, :out, :color, :id

  def initialize (id, label, abserr, relerr, addr="", disas="", func="", src="")
    @id, @label, @abserr = id, label, abserr
    @relerr = abserr == 0 ? 0 : (relerr ** (1.0/5))
    @addr, @disas, @func, @src = addr, disas, func, src
    @in, @out = [], []
    @color = 0xff
  end

  # convert to DOT format (including outgoing edges)
  def to_s
    cformat = colorf(@color)
    output =  "#{@id.to_s} [label=\""
    if ($verbose)
      output += "#{@disas.to_s} func=#{@func}' src=#{src}"
      #output += "abserr=#{@abserr.to_s} relerr=#{(@relerr ** 5.0).to_s}" +
    end
    output += "\" style=filled fillcolor=\"" + 
    "\#ff#{cformat}#{cformat}\"];\n" +
    @out.map { |id| "#{@id} -> #{id};" }.join("\n")
    output
  end

end

# a cluster of node ids
class Cluster
  attr_reader :abserr, :relerr, :name
  attr_accessor :color, :nodes

  def initialize(node)
    @name = node.func
    @nodes = [node]
    @abserr = node.relerr
    @relerr = node.relerr
    @color = 0x00
  end

  def add(node)
    @nodes << node
    @abserr = (@abserr + node.abserr)/2
    @relerr = (@relerr + node.relerr)/2
  end

  def cformat
    "\"\##{colorf(@color)}0000\""
  end

  def to_s
    err = $relative ? @relerr : @abserr
    if(err > 0 && !$collapse)
      output = "subgraph cluster_#{@name}{\n"
      output += "penwidth=6\n"
      output += "color=#{cformat}\n"
      output += "label=\"#{@name} err:#{err ** 5.0}\"\n"
      output += @nodes.map {|node| "#{node.id.to_s};"}.join("")
      output += "\n}\n"
      output += @nodes.map {|node| "#{node.to_s}"}.join("\n")
    else
      @color = 0xff - @color
      format = "\"\#ff#{colorf(@color)}#{colorf(@color)}\""
      output = "#{nodes[0].id.to_s} [label=\"#{@name} err:#{err ** 5.0}"
      output += "\" shape=box style=filled penwidth=6 fillcolor=#{format}];\n"
      found = []
      @nodes.each do |node|
        node.out.each do |id|
          update = $graph[id].id
          if(update != node.id && !found.include?(update))
            found << update
            output += "#{node.id} -> #{update}\n"
          end
        end
  #      output += (node.out.map {|id| "#{node.id} -> #{$graph[id].id};"}).join("\n");
        if(!$collapse)
  #        output += (node.in.map {|id| "#{id} -> #{nodes[0].id};"}).join("\n");
        end
      end
    end
    output
  end
end

# data structures
graph = Hash.new      # map: id => node
edges = []            # list of [src,dst] pairs
clusters = Hash.new   # map: name => cluster

# load graph from DOT file

ARGF.each_line do |line|
  if line =~ /^(\d+) \[label="([^ ]*) abserr=([^ ]*) relerr=([^ ]*) addr=([0-9a-f]*) disas='([^']*)' func='([^']*)' src=([^ ]*)"\];$/
    graph[$1.to_i] = DiffNode.new($1.to_i, $2, $3.to_f, $4.to_f, $5, $6, $7, $8)
  elsif line =~ /^(\d+) \[label="([^ ]*) abserr=([^ ]*) relerr=([^ ]*)"\];$/
    graph[$1.to_i] = DiffNode.new($1.to_i, $2, $3.to_f, $4.to_f)
  elsif line =~ /^(\d+) -> (\d+);$/
    edges << [$1.to_i, $2.to_i]       # save edge info for later
  end
end

# remove duplicate edges
edges = edges.uniq

# add all edge information to graph
edges.each do |src,dst|
  graph[src].out << dst if not graph[src].nil?
  graph[dst].in << src if not graph[dst].nil?
end

# keep only nodes with at least incoming or outgoing edge
graph.select! { |id,node| node.in.size > 0 or node.out.size > 0 }

# categorize all nodes based on function
graph.each do |id,node|
  func = node.func
  if clusters.has_key?(func)
    clusters[func].add(node)
  else
    clusters[func] = Cluster.new(node)
  end
end

# find the max error in the graph
max = 0
graph.each do |id,node|
  err = $relative ? node.relerr : node.abserr
  max = err if (err > max)
end

# color each node accordingly
factor = (max == 0) ? 0 : 0xff.to_f / max
graph.each do |id,node|
  err = $relative ? node.relerr : node.abserr
  node.color -= (err * factor).round
end

# find the max absolute error in the clusters
max = 0
clusters.each do |id,node|
  err = $relative ? node.relerr : node.abserr
  max = err if (err > max)
end

# color each cluster accordingly
factor = (max == 0) ? 0 : 0xff.to_f / max
clusters.each do |name, cluster|
  err = $relative ? cluster.relerr : cluster.abserr
  cluster.color += (err * factor).round
end

# fix edges with collapse
clusters.each do |name, cluster|
  if ($collapse || cluster.relerr <= 0)
    id = cluster.nodes[0].id
    cluster.nodes.each do |node|
      node.id = id
    end
  end
end

$graph = graph

# re-output graph in DOT format
puts "digraph trace {\nfontsize=24.0"

# output function clusters
clusters.each do |name, cluster|
  puts cluster
end

puts "}"

