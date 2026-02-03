# UNCAUGHT SPAM ANALYSIS - February 2, 2026

## CRITICAL FINDING: TEST vs PROD Discrepancy

### Memory Loss Email - CAUGHT IN TEST, MISSED IN PROD
**PROD Score**: 43 (below 50 threshold)
**TEST Score**: 118 (above 50 threshold)
**Difference**: +75 points in TEST

**Root Cause**: PROD is missing TLD Risk Assessment and Domain Reputation features
- PROD v0.8.24 is MISSING the header case sensitivity fix from v0.8.23
- This is the SAME bug we just fixed - domain extraction failing in milter mode
- From: water.hack@postpeak.shop (.shop TLD)

**Missing in PROD**:
- ❌ Domain Reputation: Suspicious domain: mail.postpeak.shop (+60 points)
- ❌ TLD Risk Assessment: Suspicious TLD: .shop (+15 points)

**RECOMMENDATION**: 
🚨 **URGENT**: PROD needs to be updated with v0.8.23 fixes immediately. The header case sensitivity bug is still present in PROD v0.8.24.

---

## Summary of Uncaught Spam

| Email | PROD | TEST | Status | Type |
|-------|------|------|--------|------|
| Memory Loss | 43 | 118 | ⚠️ TEST>PROD | Health spam (.shop TLD) |
| Check in! | 10 | -10 | ❌ Both miss | Personal email spam |
| Order $375.80 | 11 | -11 | ❌ Both miss | Fake order notification |
| Grass + Bacon Dog | 37 | -37 | ❌ Both miss | Pet health spam (.skin TLD) |
| High-severity Alert | 4 | 4 | ❌ Both miss | Account phishing |
| Switch to Value Plan | 50 | 15 | ✅ PROD catches | Telecom spam |
| Throw away glasses | 29 | -29 | ❌ Both miss | Vision health spam (.quest TLD) |

---

## Detailed Analysis

### 1. Memory Loss (.shop TLD) - CRITICAL
**From**: water.hack@postpeak.shop
**Subject**: Memory Loss Starts With These 4 Warning Signs... Do You Have Them?
**Type**: Health misinformation spam

**Why Caught in TEST**:
- TLD Risk Assessment: .shop TLD (+15)
- Domain Reputation: Suspicious domain (+60)
- Suspicious subject with excessive special characters (+25)
- Total: 118 points

**Why Missed in PROD**:
- TLD Risk Assessment NOT WORKING (domain extraction bug)
- Domain Reputation NOT WORKING (domain extraction bug)
- Only scored 43 points

**Fix Required**: Deploy v0.8.23 header case sensitivity fix to PROD

---

### 2. Check in! (hotmail.com) - Score: 10/-10
**From**: lindadesormeaux@hotmail.com
**Subject**: Check in!
**Type**: Personal email spam (likely romance/advance fee scam)

**Why Missed**:
- Perfect authentication (DKIM, SPF, DMARC pass)
- Legitimate email provider (hotmail.com)
- Generic subject line
- No obvious spam patterns detected

**Characteristics**:
- Uses legitimate free email service
- Personal-looking sender name
- Vague subject line
- Likely contains scam content in body

**Recommendations**:
1. Check body content for common scam patterns:
   - Romance scam language
   - Money requests
   - Advance fee fraud patterns
   - Inheritance scams
2. Consider sender reputation scoring for free email services
3. Analyze email body for suspicious patterns

---

### 3. Order $375.80 (dekalbcentral.net) - Score: 11/-11
**From**: Zaydyn Keller <zkeller01@dekalbcentral.net>
**Subject**: Currently, an order worth $375.80 is being activated.

**Why Missed**:
- DKIM passes (domain aligned)
- Compromised educational domain (.net)
- Generic order notification
- No strong spam indicators

**Characteristics**:
- Likely compromised account
- Educational/institutional domain
- Fake order notification
- Specific dollar amount ($375.80)

**Recommendations**:
1. Add rule for fake order notifications:
   - "order worth $X is being activated"
   - "order is being processed"
   - Specific dollar amounts in subject
2. Flag educational domains sending commercial content
3. Check for sender name mismatch (Zaydyn Keller from institutional domain)

---

### 4. Grass + Bacon Dog (.skin TLD) - Score: 37/-37
**From**: SimpleTrick@pawhop.skin
**Subject**: Grass + Bacon = Add 6 Years To Your Dog's Life?

**Why Missed**:
- .skin TLD not flagged as suspicious
- Pet health spam not strongly detected
- Only 37 points (need 50)

**Characteristics**:
- Suspicious TLD: .skin
- Pet health misinformation
- Clickbait subject
- "Simple Trick" sender name

**Recommendations**:
1. Add .skin to suspicious TLD list
2. Add pet health spam patterns:
   - "add X years to your dog's life"
   - "simple trick for dogs"
   - "grass + bacon" type formulas
3. Flag "SimpleTrick" type sender names

---

### 5. High-severity Alert (heartlandstairway.com) - Score: 4/4
**From**: ml.com, <admin@heartlandstairway.com>
**Subject**: High-severity Alert: Recent changes to account

**Why Missed**:
- Only 4 points total
- Domain reputation detected suspicious pattern but low score
- Security alert phishing not strongly triggered

**Characteristics**:
- Fake display name: "ml.com,"
- Generic domain: heartlandstairway.com
- Security alert subject
- "admin@" sender

**Recommendations**:
1. Increase scoring for security alert subjects:
   - "High-severity Alert"
   - "Recent changes to account"
   - "Unusual activity detected"
2. Flag display name/domain mismatches (ml.com vs heartlandstairway.com)
3. Increase score for "admin@" senders with security alerts

---

### 6. Switch to Value Plan (funnysnails.com) - Score: 50/15
**From**: Consumer Cellular Deals <jokes@funnysnails.com>
**Subject**: Switch to the Value Plan, Just $13.95/Mo

**Status**: ✅ CAUGHT IN PROD (exactly at threshold)

**Why Caught in PROD**:
- Scored exactly 50 points (at spam threshold)
- Sender domain mismatch detected

**Why Lower in TEST**:
- TEST shows 15 points (negative score in new version)
- Sender alignment penalties reduced

**Note**: This is borderline - PROD catches it but TEST doesn't. May need investigation.

---

### 7. Throw away glasses (.quest TLD) - Score: 29/-29
**From**: ABC Health News <MedicalUnit@probrief.quest>
**Subject**: Throw away your glasses

**Why Missed**:
- .quest TLD not flagged
- Vision health spam not detected
- Only 29 points

**Characteristics**:
- Suspicious TLD: .quest
- Vision health misinformation
- Brand impersonation: "ABC Health News"
- Medical claims

**Recommendations**:
1. Add .quest to suspicious TLD list
2. Add vision health spam patterns:
   - "throw away your glasses"
   - "never wear glasses again"
   - "restore your vision"
3. Flag fake news organization names

---

## Recommendations Summary

### URGENT (Critical)
1. **Deploy v0.8.23 to PROD immediately**
   - Header case sensitivity fix is missing in PROD v0.8.24
   - This is causing .shop spam to be missed

### High Priority
1. **Add suspicious TLDs**:
   - .skin (pet/health spam)
   - .quest (health/scam spam)

2. **Enhance fake order detection**:
   - "order worth $X is being activated"
   - "order is being processed"
   - Specific dollar amounts in subjects

3. **Improve security alert phishing detection**:
   - "High-severity Alert"
   - "Recent changes to account"
   - Increase scoring for admin@ senders with alerts

4. **Add pet health spam patterns**:
   - "add X years to your dog's life"
   - "simple trick for dogs/pets"
   - Pet health misinformation

5. **Add vision health spam patterns**:
   - "throw away your glasses"
   - "restore your vision"
   - Vision health misinformation

### Medium Priority
1. **Enhance sender name analysis**:
   - Flag "SimpleTrick" type names
   - Detect display name/domain mismatches
   - Flag fake news organization names

2. **Compromised account detection**:
   - Educational domains sending commercial content
   - Institutional domains with suspicious content

3. **Free email service reputation**:
   - Consider sender reputation for hotmail/gmail
   - Analyze body content for scam patterns

---

## Test vs Prod Parity Issues

### Critical Issue
**Memory Loss email**: PROD v0.8.24 is missing the header case sensitivity fix from v0.8.23
- This is a REGRESSION
- PROD needs immediate update

### Investigation Needed
**Switch to Value Plan**: PROD catches (50) but TEST doesn't (15)
- May indicate scoring changes between versions
- Need to verify this is intentional

---

## Action Items

1. ✅ **IMMEDIATE**: Deploy v0.8.23 header fix to PROD
2. ⚠️ **URGENT**: Add .skin and .quest to suspicious TLD list
3. ⚠️ **URGENT**: Add fake order notification patterns
4. ⚠️ **URGENT**: Enhance security alert phishing detection
5. 📋 **HIGH**: Add pet health spam patterns
6. 📋 **HIGH**: Add vision health spam patterns
7. 📋 **MEDIUM**: Enhance sender name analysis
8. 📋 **MEDIUM**: Improve compromised account detection

