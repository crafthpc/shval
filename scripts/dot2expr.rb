#!/usr/bin/env ruby
require 'set'

$ids = Set.new          # all node ids
$label = Hash.new       # id -> value/operation (string)
$children = Hash.new    # parent => [child]
$parent = Hash.new      # child => parent

def print_expr(e)
  if not $children.has_key?(e)      # leaf
    print $label[e]
  elsif $children[e].size == 1      # unary
    print $label[e]
    print_expr($children[e][0])
  else                              # binary
    print "("
    print_expr($children[e][0])
    print $label[e]
    print_expr($children[e][1])
    print ")"
  end
end

ARGF.each_line do |line|
  if line =~ /^(\d+) \[label="([^ ]+)/ then             # new node
    $label[$1] = $2
    $ids << $1
  elsif line =~ /^(\d+) -> (\d+)/ then                  # new edge
    $children[$2] = [] if not $children.has_key?($2)
    $children[$2] << $1
    $parent[$1] = $2
    $ids << $2
  end
end

$ids.each do |id|
  if not $parent.has_key?(id)
    print_expr(id)                  # print each root
  end
end
