# Remaining Uncaught Spam Analysis (v0.8.25)

## Summary
After fixing the milter mode bug, 6 spam emails still score below 50 (spam threshold).

## Emails Still Missed

### 1. Check in! (hotmail.com) - Score 10
**From**: lindadesormeaux@hotmail.com  
**Subject**: Check in!  
**Issue**: Generic phishing with perfect authentication
- ✅ DKIM, SPF, DMARC all pass
- ❌ No suspicious patterns detected
- ❌ Generic subject line not flagged
- **Recommendation**: Add generic greeting + vague subject pattern detection

### 2. Order $375.80 (dekalbcentral.net) - Score 11
**From**: zkeller01@dekalbcentral.net  
**Subject**: Currently, an order worth $375.80 is being activated.  
**Issue**: Compromised educational domain sending fake orders
- ✅ DKIM passes
- ❌ Educational domain (.net) sending commercial content not flagged strongly enough
- ❌ Fake order pattern not detected
- **Recommendation**: Enhance Domain Business Mismatch for educational domains + fake order patterns

### 3. Grass + Bacon (.skin) - Score 12
**From**: SimpleTrick@pawhop.skin  
**Subject**: Grass + Bacon = Add 6 Years To Your Dog's Life?  
**Issue**: Pet health spam with .skin TLD
- ✅ Product Spam detects .skin TLD (+25)
- ✅ Context Analysis detects exclamation marks
- ❌ Score reduced by "floral" industry context (wrong detection)
- ❌ Health spam patterns not detected
- **Recommendation**: Fix "floral" false detection, add pet health spam patterns

### 4. High-severity Alert (heartlandstairway.com) - Score 4
**From**: admin@heartlandstairway.com  
**Subject**: High-severity Alert: Recent changes to account  
**Issue**: Security alert phishing
- ✅ Domain Reputation detects suspicious pattern
- ❌ "High-severity Alert" + "changes to account" not flagged
- ❌ Generic "admin@" sender not flagged
- **Recommendation**: Add security alert phishing patterns

### 5. Switch to Value Plan (funnysnails.com) - Score 15
**From**: jokes@funnysnails.com  
**Subject**: Switch to the Value Plan, Just $13.95/Mo  
**Issue**: Telecom spam with misaligned domains
- ✅ Sender Alignment detects domain mismatch
- ✅ Server Role Analysis detects suspicious domain
- ❌ Score reduced by "tech_newsletter" context (wrong)
- ❌ Pricing + plan language not flagged
- **Recommendation**: Fix tech_newsletter false detection, add telecom spam patterns

### 6. Throw away glasses (.quest) - Score 4
**From**: MedicalUnit@probrief.quest  
**Subject**: Throw away your glasses  
**Issue**: Vision health spam with .quest TLD
- ✅ Product Spam detects .quest TLD (+25)
- ✅ Context Analysis detects exclamation marks
- ❌ Score reduced by "tech_newsletter" context (wrong)
- ❌ Vision health spam patterns not detected
- **Recommendation**: Fix tech_newsletter false detection, add vision health spam patterns

## Common Issues

### 1. Context Analysis False Positives
- "floral" context incorrectly applied to pet health spam
- "tech_newsletter" context incorrectly applied to telecom and health spam
- These reduce scores by 50-70%, causing spam to be missed

### 2. Missing Spam Patterns
- Generic phishing (vague subjects + generic greetings)
- Fake order notifications
- Security alert phishing
- Pet health spam
- Vision health spam
- Telecom/plan spam

### 3. Compromised Domain Detection
- Educational domains sending commercial content need stronger penalties
- Generic admin@ senders from suspicious domains

## Recommended Fixes (Priority Order)

### High Priority
1. **Fix Context Analysis false positives**
   - Review "floral" detection (catching pet health spam)
   - Review "tech_newsletter" detection (catching telecom/health spam)
   - These are causing 50-70% score reductions on spam

2. **Add fake order notification patterns**
   - "order worth $X is being activated"
   - "order is being processed"
   - From non-commerce domains

3. **Add security alert phishing patterns**
   - "High-severity Alert" + "changes to account"
   - "Suspicious activity" + "verify immediately"
   - Generic admin@ senders

### Medium Priority
4. **Enhance Domain Business Mismatch**
   - Educational domains (.edu, .net with "school" names) sending orders
   - Government domains sending commercial content
   - Stronger penalties for institutional domain abuse

5. **Add health spam patterns**
   - Pet health: "Add X years to your dog's life"
   - Vision health: "Throw away your glasses"
   - Medical claims from non-medical domains

6. **Add telecom spam patterns**
   - "Switch to X plan"
   - "$X.XX/Mo" pricing
   - "Value plan" language

### Low Priority
7. **Generic phishing detection**
   - Vague subjects ("Check in!", "Hello", "Hi")
   - Generic greetings with no specific content
   - From free email providers (hotmail, gmail)

## Expected Impact
Fixing Context Analysis false positives alone would increase scores by 50-70 points:
- Grass + Bacon: 12 → 62-82
- Throw away glasses: 4 → 54-74
- Switch to Value Plan: 15 → 65-85

Adding missing patterns would catch the remaining spam:
- Check in!: 10 → 60+
- Order $375.80: 11 → 61+
- High-severity Alert: 4 → 54+
