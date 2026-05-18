<?php

/**
 * @covers \QubitSlug
 *
 * @internal
 */
class QubitSlugTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @dataProvider providerAll
     */
    public function testSlugifyRestrictive(string $given, string $expectedRestrictive, string $expectedPermissive): void
    {
        $this->assertSame(
            $expectedRestrictive,
            QubitSlug::slugify($given, QubitSlug::SLUG_RESTRICTIVE)
        );
    }

    /**
     * @dataProvider providerAll
     */
    public function testSlugifyPermissive(string $given, string $expectedRestrictive, string $expectedPermissive): void
    {
        $this->assertSame(
            $expectedPermissive,
            QubitSlug::slugify($given, QubitSlug::SLUG_PERMISSIVE)
        );
    }

    public function providerAll(): array
    {
        return [
            // FORMAT: GIVEN, EXPECTED_RESTRICTIVE, EXPECTED_PERMISSIVE

            // Basic ASCII and normalization
            ['test slug', 'test-slug', 'test-slug'],
            ['test-slug', 'test-slug', 'test-slug'],
            ['TestSlug', 'testslug', 'TestSlug'],  // Follow isAscii path
            ['test----slug', 'test-slug', 'test-slug'],
            ['Test Slug', 'test-slug', 'Test-Slug'],
            ['Test Slug 123', 'test-slug-123', 'Test-Slug-123'],

            // Apostrophes are removed
            ["Test 'Slug'", 'test-slug', 'Test-Slug'],

            // Allowed safe punctuation in permissive; becomes dashes in restrictive
            ['a_-~:;,=*@b', 'a-b', 'a_-~:;,=*@b'],

            // Accented Latin transliteration vs preservation
            ['Tést Slug', 'test-slug', 'Tést-Slug'],
            ['Tést SLÜG', 'test-slug', 'Tést-SLÜG'],

            // Cyrillic preserved in permissive, dropped in restrictive
            ['TEST АБВ абв', 'test', 'TEST-АБВ-абв'],

            // Arabic letters and digits
            ['اختبار سلاج 123', '123', 'اختبار-سلاج-123'],
            ['اختبار', '', 'اختبار'],

            // Disallowed in permissive: collapse to dash
            ['Foo – Bar', 'foo-bar', 'Foo-Bar'],        // en dash U+2013
            ['Foo — Bar', 'foo-bar', 'Foo-Bar'],        // em dash U+2014
            ['Foo−Bar', 'foo-bar', 'Foo-Bar'],          // minus sign U+2212
            ['No…yes', 'no-yes', 'No-yes'],             // ellipsis U+2026
            ['A • B', 'a-b', 'A-B'],                    // bullet U+2022
            ['A · B', 'a-b', 'A-B'],                    // middle dot U+00B7
            ['Price €100', 'price-100', 'Price-100'],   // euro sign U+20AC
            ['Temp 20°C', 'temp-20-c', 'Temp-20-C'],    // degree sign U+00B0
            ['© 2024', '2024', '2024'],                 // copyright U+00A9
            ['£5', '5', '5'],                           // pound sign U+00A3
            ['“Hello”', 'hello', 'Hello'],              // curly quotes
            ['‘A’', 'a', 'A'],                          // curly single quotes

            // Spaces and format/controls
            ["A\u{00A0}B", 'a-b', 'A-B'],              // NBSP U+00A0
            ["A\u{200D}B", 'ab', 'A-B'],               // ZWJ U+200D (removed in restrictive)

            // Additional format controls (Cf)
            ["A\u{200C}B", 'ab', 'A-B'],               // ZWNJ U+200C (removed in restrictive)
            ["A\u{00AD}B", 'ab', 'A-B'],               // soft hyphen U+00AD (removed in restrictive)
            ["A\u{FE0F}B", 'ab', 'A-B'],               // variation selector-16 U+FE0F (removed in restrictive)

            // Line/paragraph separators (Zl/Zp)
            ["A\u{2028}B", 'a-b', 'A-B'],              // line sep U+2028
            ["A\u{2029}B", 'a-b', 'A-B'],              // paragraph sep U+2029

            // Control characters (Cc)
            ['A'.chr(7).'B', 'a-b', 'A-B'],            // BEL control

            // Additional dash punctuation (Pd)
            ["A\u{2011}B", 'a-b', 'A-B'],              // non-breaking hyphen U+2011
            ["A\u{2012}B", 'a-b', 'A-B'],              // figure dash U+2012
            ["A\u{2015}B", 'a-b', 'A-B'],              // horizontal bar U+2015

            // Combining marks (M)
            ["e\u{0301} slug", 'e-slug', 'e-slug'],     // e + combining acute
            ["Cafe\u{0301}", 'cafe', 'Cafe'],            // trailing combining mark trimmed

            // Non-ASCII digits (N) — restrictive drops them
            ["\u{0661}\u{0662}\u{0663}", '', "\u{0661}\u{0662}\u{0663}"], // Arabic-Indic ١٢٣

            // Emoji and pictographs
            ['Hi 😀', 'hi', 'Hi'],
        ];
    }
}
