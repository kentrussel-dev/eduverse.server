using System.Text;
using System.Text.RegularExpressions;

namespace EduVerse.Server.Realtime
{
    /// <summary>
    /// Keeps chat safe for students: masks bad words (English and Filipino) and hides
    /// links, emails and phone numbers so kids don't share personal details.
    /// </summary>
    public static class ChatFilter
    {
        public const int MaxLength = 200;

        private static readonly string[] BlockedWords =
        {
            "fuck", "fck", "fuk", "shit", "bitch", "bastard", "asshole", "dick", "pussy", "cunt",
            "slut", "whore", "nigger", "nigga", "retard", "fag", "faggot", "porn", "sex", "nude", "nudes",
            "puta", "putang", "putangina", "tangina", "tang ina", "gago", "gaga", "bobo", "tanga",
            "ulol", "tarantado", "pakyu", "pakshet", "kupal", "hayop ka", "burat", "titi", "kantot"
        };

        private static readonly Regex BlockedPattern = new(
            @"\b(" + string.Join("|", BlockedWords.Select(w => Regex.Escape(w).Replace(@"\ ", @"\s*"))) + @")\w*",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex PersonalInfo = new(
            @"(https?://\S+|www\.\S+|\b[\w.-]+\.(com|net|org|ph|io|gg|me|tv|ly)\b\S*" +
            @"|[\w.+-]+@[\w-]+\.[\w.]+" +
            @"|(\+?\d[\d\s().-]{6,}\d))",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        public record Result(string Text, bool WasFiltered);

        public static Result Clean(string? input)
        {
            var text = Regex.Replace(input ?? string.Empty, @"\s+", " ").Trim();
            if (text.Length > MaxLength)
            {
                text = text[..MaxLength];
            }

            var filtered = false;

            // Match against a leetspeak-normalized copy; it has the same length, so indexes line up.
            var normalized = Normalize(text);
            var masked = new StringBuilder(text);
            foreach (Match match in BlockedPattern.Matches(normalized))
            {
                filtered = true;
                for (var i = match.Index; i < match.Index + match.Length; i++)
                {
                    if (!char.IsWhiteSpace(masked[i]))
                    {
                        masked[i] = '*';
                    }
                }
            }
            text = masked.ToString();

            var withoutInfo = PersonalInfo.Replace(text, "[hidden]");
            if (withoutInfo != text)
            {
                filtered = true;
                text = withoutInfo;
            }

            return new Result(text, filtered);
        }

        private static string Normalize(string text)
        {
            var chars = text.ToLowerInvariant().ToCharArray();
            for (var i = 0; i < chars.Length; i++)
            {
                chars[i] = chars[i] switch
                {
                    '0' => 'o',
                    '1' or '!' or '|' => 'i',
                    '3' => 'e',
                    '4' or '@' => 'a',
                    '5' or '$' => 's',
                    '7' => 't',
                    _ => chars[i]
                };
            }
            return new string(chars);
        }
    }
}
