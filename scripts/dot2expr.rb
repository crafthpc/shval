#!/usr/bin/env ruby
#
# Convert a computation graph produced by the "trace" tool (and stored in DOT
# format) to real-valued expressions.
#
# This file is part of SHVAL. For details, see https://github.com/lam2mo/shval
#
# Please also see the LICENSE file for our notice and the LGPL.
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

require 'set'

$ids = Set.new          # all node ids
$label = Hash.new       # id -> value/operation (string)
$children = Hash.new    # parent => [child]
$parent = Hash.new      # child => parent

def print_expr(e)
  if not $children.has_key?(e)      # leaf
    print $label[e]
  elsif $children[e].size == 1      # unary
    print "("
    print $label[e]
    print "("
    print_expr($children[e][0])
    print ")"
    print ")"
  else                              # binary
    print "("
    print_expr($children[e][0])
    print $label[e]
    print_expr($children[e][1])
    print ")"
  end
end

ARGF.each_line do |line|
  if line =~ /^(\d+) \[label="([^ "]+)/ then             # new node
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
    puts
  end
end
