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

require 'getoptlong'
require 'set'

#
# global variables and data structures
#

$int_pct = nil          # percentage of intermediates to separate out
$ids = Set.new          # all node ids
$label = Hash.new       # id -> value/operation (string)
$children = Hash.new    # parent => [child]
$parent = Hash.new      # child => parent
$uses = Hash.new(0)     # id -> uses

#
# helper functions
#

def count_uses(e)
  $uses[e] += 1
  if $children.has_key?(e)
    $children[e].each {|c| count_uses(c)}
  end
end

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

#
# main routine
#

# parse command-line parameters
opts = GetoptLong.new(
  [ '--help', '-h', GetoptLong::NO_ARGUMENT ],
  [ '--intermediates', '-i', GetoptLong::REQUIRED_ARGUMENT ],
)
opts.each do |opt, arg|
  case opt
  when '--help'
    puts <<-EOF
dot2expr [options] <dot-filename>

  -h, --help                    print usage text
  -i, --intermediates <p>       convert p% of outputs to intermediates
    EOF
  when '--intermediates'
    $int_pct = arg.to_f
  end
end
if ARGV.length != 1
  puts "Missing filename (run w/ --help for usage info)"
  exit
end

IO.foreach(ARGV.shift) do |line|
  if line =~ /^(\d+) \[label="([^ "]+)/ then            # new node
    $label[$1] = $2
    $ids << $1
  elsif line =~ /^(\d+) -> (\d+)/ then                  # new edge
    $children[$2] = [] if not $children.has_key?($2)
    $children[$2] << $1
    $parent[$1] = $2
    $ids << $2
  end
end

if not $int_pct.nil?

  # calculate intermediate usage information
  $ids.each { |id| count_uses(id) if not $parent.has_key?(id) }

  # sort intermediates in order of decreasing use
  intermediates = $uses.to_a.sort { |a,b| b[1] <=> a[1] }

  # separate out half of intermediates into a temporary variable
  tmps = intermediates.take(intermediates.size * $int_pct)
  tmps.each_index do |i|
    id = tmps[i][0]
    old_label = $label[id]
    new_label = "t#{i}"
    print "#{new_label} = "
    print_expr(id)
    puts
    $label[id] = new_label
    $children[id] = []
  end

end

# print each root
$ids.each do |id|
  if not $parent.has_key?(id)
    print_expr(id)
    puts
  end
end
