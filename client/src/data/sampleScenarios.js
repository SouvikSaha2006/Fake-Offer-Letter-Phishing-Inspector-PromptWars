/**
 * Pre-configured Forensic Test Scenarios for PhishGuard Inspector
 */

export const TEST_SCENARIOS = [
  {
    id: 'legitimate_offer',
    name: 'Scenario 1: Legitimate Enterprise Offer',
    badge: 'SAFE',
    type: 'text',
    content: `From: talent-acquisition@crowdstrike.com
Subject: Formal Offer of Employment - Senior Systems Reliability Engineer

Dear Alex Morgan,

On behalf of CrowdStrike, Inc., we are delighted to offer you the position of Senior Systems Reliability Engineer. This is a full-time, exempt position reporting directly to the Director of Cloud Infrastructure.

Compensation & Benefits Overview:
- Base Annual Salary: $165,000 USD, payable semi-monthly in accordance with standard corporate payroll practices.
- Annual Incentive Bonus: Targeted at 15% of your base salary, contingent upon company and individual milestone objectives.
- Equity Grant: Subject to Board approval, you will be granted restricted stock units (RSUs) valued at $60,000 under the 2024 Equity Incentive Plan.
- Health & Wellness: Comprehensive medical, dental, vision, and 401(k) match effective on your official start date.

Equipment & Onboarding:
All enterprise workstation hardware (including corporate laptop, secure YubiKey 2FA tokens, and peripheral monitor accessories) will be pre-configured and shipped directly to your residential address by our IT Operations team at zero expense to you.

Please review and execute this letter via our secure DocuSign portal by Friday, October 30, 2026. If you have any inquiries, feel free to reach out to our Talent Acquisition team at talent-acquisition@crowdstrike.com or visit our careers verification portal at https://crowdstrike.com/careers.

Sincerely,
Elena Rostova
Senior Director of Talent Operations
CrowdStrike, Inc.`
  },
  {
    id: 'cashier_check_scam',
    name: 'Scenario 2: Cashier Check & Equipment Phishing',
    badge: 'CRITICAL',
    type: 'text',
    content: `From: hr-recruitment-team@google-careers-portal.com
Subject: IMMEDIATE JOB OFFER: Data Entry & AI Processing Specialist

Congratulations! Following a review of your resume on Indeed, you have been selected without further interview for the position of Remote Operations Associate.

Terms of Employment:
- Hourly Pay: $62.50 per hour during 2-week training period ($85.00/hr afterwards).
- Weekly working hours: Flexible 20-30 hours per week.

OFFICE EQUIPMENT ALLOCATIONS & MANDATORY PROCEDURE:
To establish your mini-office, a certified Cashier's Check for $4,850.00 will be express-mailed to your home address via FedEx. Upon receipt, you are required to deposit the check into your personal bank account within 24 hours. 

Once funds show in your account, you must immediately wire $4,200 via Zelle or Western Union to our accredited procurement vendor to dispatch your Apple MacBook Pro M3, encrypted laser printer, and specialized CRM time-tracking software. You may retain the remaining $650 as your upfront sign-on bonus.

CRITICAL INSTRUCTION:
Your assigned hiring manager Mr. David Vance is waiting to finalize your paperwork. Download Telegram immediately and send a direct message to @google_hiring_manager_david to receive your check tracking number.

Failure to confirm within 24 hours will forfeit this offer.

Human Resources Department
Careers Portal Operations Team
hr-recruitment-team@google-careers-portal.com`
  },
  {
    id: 'rental_wire_fraud',
    name: 'Scenario 3: Apartment Rental Wire Fraud',
    badge: 'FRAUD',
    type: 'text',
    content: `From: reverend.john.properties@gmail.com
Subject: URGENT: Luxury 2-Bedroom Condo Lease Agreement - Keys Dispatch

Hello Dear Applicant,

Thank you for your interest in leasing our fully furnished 2-bedroom luxury penthouse unit at 450 Lexington Ave. The rent is $1,200/month (all utilities included including high-speed fiber internet and underground parking).

I am currently away on an emergency missionary assignment in West Africa with the United Nations humanitarian mission, which is why I cannot meet you in person for an open house viewing. However, the property is vacant and ready for immediate move-in.

Due to extremely high demand and over 35 applicants waiting, I need to secure the unit for you today. You must make a refundable holding deposit of $1,500 (first month rent + security deposit) via Cash App ($ReverendJohnHome) or Zelle to my overseas logistics coordinator today. Alternatively, you can deposit $1,500 in Bitcoin to our corporate wallet: 0x71C7656EC7ab88b098defB751B7401B5f6d8976F.

As soon as the payment confirmation receipt is forwarded, the FedEx courier dispatch will release the keys, gate fobs, and stamped lease contract directly to your doorstep within 12 hours.

Do not delay as this listing will be transferred to the next candidate by 5:00 PM today.

Blessings,
Rev. Johnathan Bradley
Property Owner & UN Mission Director
reverend.john.properties@gmail.com`
  }
];
