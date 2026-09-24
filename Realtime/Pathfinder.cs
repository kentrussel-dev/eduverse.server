namespace EduVerse.Server.Realtime
{
    /// <summary>A* over a room's tile grid. Moves in 8 directions but never cuts a blocked corner.</summary>
    public static class Pathfinder
    {
        private static readonly (int dx, int dy)[] Steps =
        {
            (1, 0), (-1, 0), (0, 1), (0, -1), (1, 1), (1, -1), (-1, 1), (-1, -1)
        };

        /// <summary>Returns the tiles to walk after <paramref name="start"/>, ending at the goal; empty if unreachable.</summary>
        public static List<(int X, int Y)> FindPath(bool[,] walkable, (int X, int Y) start, (int X, int Y) goal)
        {
            var width = walkable.GetLength(0);
            var depth = walkable.GetLength(1);
            bool Open(int x, int y) => x >= 0 && y >= 0 && x < width && y < depth && walkable[x, y];

            if (start == goal || !Open(goal.X, goal.Y))
            {
                return new List<(int, int)>();
            }

            var cameFrom = new Dictionary<(int, int), (int, int)>();
            var cost = new Dictionary<(int, int), double> { [start] = 0 };
            var queue = new PriorityQueue<(int X, int Y), double>();
            queue.Enqueue(start, 0);

            while (queue.TryDequeue(out var current, out _))
            {
                if (current == goal)
                {
                    var path = new List<(int, int)>();
                    for (var node = goal; node != start; node = cameFrom[node])
                    {
                        path.Add(node);
                    }
                    path.Reverse();
                    return path;
                }

                foreach (var (dx, dy) in Steps)
                {
                    var nx = current.X + dx;
                    var ny = current.Y + dy;
                    if (!Open(nx, ny))
                    {
                        continue;
                    }
                    var diagonal = dx != 0 && dy != 0;
                    if (diagonal && (!Open(current.X + dx, current.Y) || !Open(current.X, current.Y + dy)))
                    {
                        continue;
                    }

                    var next = (nx, ny);
                    var nextCost = cost[current] + (diagonal ? 1.414 : 1.0);
                    if (!cost.TryGetValue(next, out var known) || nextCost < known)
                    {
                        cost[next] = nextCost;
                        cameFrom[next] = current;
                        var ddx = Math.Abs(goal.X - nx);
                        var ddy = Math.Abs(goal.Y - ny);
                        var heuristic = Math.Max(ddx, ddy) + 0.414 * Math.Min(ddx, ddy);
                        queue.Enqueue(next, nextCost + heuristic);
                    }
                }
            }

            return new List<(int, int)>();
        }
    }
}
