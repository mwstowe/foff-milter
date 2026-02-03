# Production vs Test Score Discrepancy Analysis

## Root Cause: Recent Code Changes Not Deployed to Production

Production is running **v0.8.25+35fdfc35** (before recent improvements)
Test is running **v0.8.25+e6769e0** (after 6 commits of improvements)

## Key Changes Between Production and Test

### Commit 67c1c40: "Fix final 3 test failures - 100% test success"
**Added ESP whitelists that dramatically reduce false positives:**

1. **Brand Impersonation ESP Whitelist**
   - Added: sendgrid, medium, substack, mailchimp
   - Effect: Skips brand detection for legitimate newsletter platforms
   - Impact: -85 to -100 points for SendGrid emails

2. **Link Analyzer Payment Processor Whitelist**
   - Added: ngpvan.com, everyaction.com, actblue.com
   - Effect: Political fundraising links no longer flagged
   - Impact: -20 to -50 points for fundraising emails

### Commit c76559b: "Catch all remaining uncaught spam"
**Added spam detection patterns that increase some scores:**

1. **Health Spam Patterns**
   - Added: Pet health, vision, generic phishing
   - Effect: Catches more health-related spam
   - Side effect: May trigger on legitimate health products

2. **Product Spam Patterns**
   - Added: Telecom spam patterns
   - Effect: Catches fake telecom offers
   - Side effect: May trigger on legitimate retailers

3. **Domain Business Mismatch**
   - Enhanced: Educational/government domain abuse detection
   - Effect: Catches compromised institutional accounts

## Score Comparison: Production vs Test

### Emails with HUGE Improvements (Test much better)

| Email | Prod | Test | Diff | Reason |
|-------|------|------|------|--------|
| Just For You (1-800-Flowers) | 304 | -7 | **-311** | ESP whitelist + business context |
| New from Le Creuset | 269 | -24 | **-293** | ESP whitelist + legitimate retailer |
| More comfort (Mack Weldon) | 93 | -137 | **-230** | SendGrid ESP whitelist |
| GIVEAWAY 🎁 | 208 | -21 | **-229** | ESP whitelist + seasonal context |
| Snow Joe (TOUCHDOWN SAVINGS) | 99 | -128 | **-227** | SendGrid ESP whitelist |

### Emails with Moderate Improvements

| Email | Prod | Test | Diff | Reason |
|-------|------|------|------|--------|
| Bruce Ronn (Facebook group) | 76 | -38 | **-114** | Social platform recognition |
| DREAMOSIS (Gadget Flow) | 150 | 97 | **-53** | Partial ESP recognition |
| AdaptHealth | 85 | 55 | **-30** | Healthcare marketplace context |

### Emails with Worse Scores (Test worse)

| Email | Prod | Test | Diff | Reason |
|-------|------|------|------|--------|
| Dish duty (Sears) | 150 | 226 | **+76** | New link analysis patterns |
| Projects we love (Kickstarter) | 121 | 173 | **+52** | New brand detection patterns |
| Senior Developers (Medium) | 55 | 89 | **+34** | New brand detection patterns |

### Emails with No Change

| Email | Prod | Test | Diff | Reason |
|-------|------|------|------|--------|
| Facebook 2FA code | 76 | 76 | 0 | Phishing rule unchanged |

## Why Production Tagged Them as Spam

### Snow Joe (Prod: 99, Test: -128)
**Production scoring:**
- Product Spam: +35 (reward/offer promotion)
- Brand Impersonation: +85 (no ESP whitelist)
- Authentication bonus reduced: -30
- **Total: ~99**

**Test scoring:**
- Product Spam: +10 (reduced)
- Brand Impersonation: **0 (SendGrid ESP whitelist)**
- ESP Infrastructure: **-100 (Major ESP)**
- Authentication bonus: -30
- **Total: -128**

**Difference: SendGrid ESP whitelist saves -227 points**

### Mack Weldon (Prod: 93, Test: -137)
Same pattern as Snow Joe - SendGrid ESP whitelist is the key difference.

### Le Creuset (Prod: 269, Test: -24)
**Production scoring:**
- High product/promotional scoring
- No ESP recognition
- **Total: 269**

**Test scoring:**
- ESP Infrastructure recognized
- Business context applied
- Legitimate retailer patterns
- **Total: -24**

**Difference: -293 points from ESP + business context**

## Remaining False Positives in Test

Even with improvements, 6 emails still flagged:

1. **Sears (226)** - Cross-domain links to ShopYourWay
2. **Kickstarter (173)** - Cross-domain + brand detection
3. **Gadget Flow (97)** - Health/product spam triggers
4. **Medium (89)** - Brand detection in content
5. **Facebook (76)** - Password phishing rule
6. **AdaptHealth (55)** - Healthcare marketplace

## Recommendations

### For Production Deployment
**Deploy current code immediately** - Will fix most false positives:
- Snow Joe: 99 → -128 ✅
- Mack Weldon: 93 → -137 ✅
- Le Creuset: 269 → -24 ✅
- 1-800-Flowers: 304 → -7 ✅
- Many others improved

### For Remaining False Positives
Need additional fixes for the 6 emails still flagged in test:
1. Add Sears/ShopYourWay relationship to link analyzer
2. Add Kickstarter ESP infrastructure support
3. Refine brand patterns ("att", "costco" too broad)
4. Add facebookmail.com to phishing whitelist
5. Add adapthealthmarketplace.com to health whitelist
6. Add thegadgetflow.com to product whitelist

## Conclusion

**The "false positives" in production are actually correct behavior for the old code.**

The recent improvements (commits 67c1c40 and c76559b) dramatically reduced false positives by:
- Adding ESP whitelists (SendGrid, SparkPost, etc.)
- Improving business context detection
- Better handling of legitimate retailers

**Action: Deploy current code to production to fix most false positives.**
