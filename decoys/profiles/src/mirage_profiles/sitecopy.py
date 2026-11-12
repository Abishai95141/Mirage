"""Readable copy for the decoy web site, by industry (the profile's ``title_suffix``).

Faker's ``sentence`` and ``paragraph`` draw random English words ("There professional heavy
happy."), which a person spots at once. The site's text is assembled from these hand-written,
generic phrases instead; Faker still supplies names, cities and companies.
"""

from __future__ import annotations

INDUSTRY: dict[str, dict[str, list]] = {
    "Logistics": {
        "hero": [
            "Freight that arrives when you said it would",
            "Warehousing and delivery you can plan around",
            "Regional logistics without the guesswork",
        ],
        "services": [
            (
                "Road freight",
                "Full and part loads across the region, tracked from pickup to delivery.",
            ),
            ("Warehousing", "Secure, racked storage with same-day pick, pack and dispatch."),
            (
                "Last-mile delivery",
                "Scheduled drops to shops, sites and homes, with proof of delivery.",
            ),
            (
                "Customs clearance",
                "Paperwork handled by our brokers so shipments are not held at the border.",
            ),
            (
                "Fleet management",
                "Maintenance, routing and driver scheduling for your own vehicles.",
            ),
        ],
        "about": [
            "We started with two vans and a rented unit, and we still answer the phone ourselves.",
            "Our dispatchers know the routes, the loading bays and most of the drivers by name.",
        ],
    },
    "Dental": {
        "hero": [
            "Gentle, modern dentistry for the whole family",
            "Your local practice for healthy smiles",
            "Check-ups, hygiene and treatment under one roof",
        ],
        "services": [
            (
                "Check-ups and hygiene",
                "Routine examinations and professional cleaning, with reminders when you are due.",
            ),
            (
                "Fillings and crowns",
                "Tooth-coloured restorations that last, fitted by experienced dentists.",
            ),
            (
                "Teeth whitening",
                "Safe in-practice and take-home whitening, supervised from start to finish.",
            ),
            (
                "Emergency appointments",
                "Same-day slots kept free every morning for pain and breakages.",
            ),
            (
                "Children's dentistry",
                "Friendly first visits that help children feel at ease in the chair.",
            ),
        ],
        "about": [
            "Our team of dentists and hygienists has looked after local families for years.",
            "We take time to explain every option and its cost before any treatment begins.",
        ],
    },
    "Consulting": {
        "hero": [
            "Practical advice for growing businesses",
            "Clear strategy, delivered with your team",
            "Helping owners make better decisions, faster",
        ],
        "services": [
            (
                "Business planning",
                "Budgets, forecasts and plans that your bank and your team can work with.",
            ),
            (
                "Operations review",
                "We find where time and money leak out of your processes, and fix it.",
            ),
            (
                "Interim management",
                "Experienced managers who step in while you recruit or restructure.",
            ),
            ("Training", "Workshops for managers on planning, delegation and running projects."),
            (
                "Funding support",
                "Grant and loan applications prepared and reviewed before you submit them.",
            ),
        ],
        "about": [
            "Our consultants have run businesses themselves, so our advice is grounded in practice.",
            "We work alongside your people rather than handing over a report and leaving.",
        ],
    },
    "Studio": {
        "hero": [
            "Design and photography that gets noticed",
            "A creative studio for brands that want to stand out",
            "Ideas, images and websites, made in-house",
        ],
        "services": [
            (
                "Brand identity",
                "Logos, colours and guidelines that make your business recognisable.",
            ),
            (
                "Photography",
                "Product, portrait and event photography in our studio or on location.",
            ),
            ("Web design", "Fast, accessible websites that are easy for you to update."),
            (
                "Print and packaging",
                "Brochures, labels and packaging, from first sketch to the printer.",
            ),
            ("Video", "Short films for social media, recruitment and product launches."),
        ],
        "about": [
            "We are a small team of designers and photographers who like to keep projects personal.",
            "Every project starts with a conversation about what you want people to feel.",
        ],
    },
    "Supplies": {
        "hero": [
            "Trade supplies, delivered next day",
            "Everything your site needs, from one supplier",
            "Stock you can count on, prices you can plan with",
        ],
        "services": [
            ("Trade accounts", "Credit terms and account pricing for regular customers."),
            (
                "Next-day delivery",
                "Order by 4pm for delivery the next working day across the region.",
            ),
            ("Bulk orders", "Pallet quantities at reduced rates, with scheduled deliveries."),
            ("Click and collect", "Order online and collect from the counter within the hour."),
            (
                "Product advice",
                "Staff with trade experience who can help you choose the right materials.",
            ),
        ],
        "about": [
            "We hold thousands of lines in stock at our warehouse, so we rarely have to say no.",
            "Many of our customers have had accounts with us since the day we opened.",
        ],
    },
    "Partners": {
        "hero": [
            "Accounting and advice you can rely on",
            "Straightforward professional services for local businesses",
            "Partners in your business, not just your accounts",
        ],
        "services": [
            (
                "Accounts and tax",
                "Year-end accounts and tax returns, filed on time and explained clearly.",
            ),
            ("Payroll", "Monthly payroll, payslips and filings handled for you."),
            ("Bookkeeping", "Up-to-date books so you always know where your business stands."),
            ("Business advice", "Help with pricing, cash flow and planning for growth."),
            ("Company formation", "Setting up a new company correctly from the first day."),
        ],
        "about": [
            "The partnership has served owner-managed businesses in the area for many years.",
            "You will always deal with the same partner, who knows your business.",
        ],
    },
    "Systems": {
        "hero": [
            "IT support that keeps your business running",
            "Managed IT and networks for small offices",
            "Reliable systems, so you can get on with your work",
        ],
        "services": [
            (
                "Managed IT support",
                "A help desk for your staff and proactive monitoring of your machines.",
            ),
            ("Networks and Wi-Fi", "Office networks designed, installed and kept secure."),
            (
                "Cloud and email",
                "Moving your email and files to the cloud, without the disruption.",
            ),
            (
                "Backup and recovery",
                "Backups that are tested, so you can recover when something goes wrong.",
            ),
            ("Hardware supply", "Laptops, printers and servers sourced, set up and delivered."),
        ],
        "about": [
            "Our engineers are based locally and can be on site the same day when it matters.",
            "We look after offices from a handful of people to a few hundred.",
        ],
    },
}

INTRO = [
    "{company} has worked with clients across the region since {year}.",
    "Since {year}, {company} has built its reputation on doing the job properly.",
    "Customers have trusted {company} since {year}.",
]
ABOUT = [
    "We are based in {city} and serve customers across the surrounding area.",
    "Most of our new customers come to us on the recommendation of existing ones.",
    "We believe in clear prices, honest advice and doing what we say we will do.",
    "Our team brings together people with long experience and fresh ideas.",
    "We invest every year in training, equipment and the systems that support our work.",
    "If you would like to know more, call us or send a message through the contact page.",
]
POST_BODY = [
    "We are often asked about {service_lower}, so we have put together a few notes here.",
    "Over the past year we have worked with more customers than ever before, and we are grateful to every one of them.",
    "The details matter: planning ahead saves time, money and a lot of stress later on.",
    "Our team in {city} has been busy, and we wanted to share some of what we have learned.",
    "As always, if you have questions, get in touch and we will be happy to help.",
    "We would like to thank {name} for their help in putting this together.",
    "Small changes, made consistently, tend to make the biggest difference over time.",
    "We will share more news here over the coming months, so check back soon.",
    "Feedback from customers shapes how we work, and this is a good example of that.",
    "It is easy to put this off, but a little attention now avoids larger problems later.",
]
POST_TITLES = [
    "{n} things to know about {service_lower}",
    "Welcome {name} to the team",
    "Case study: how we helped {client}",
    "Our new office in {city}",
    "Holiday opening hours",
    "{first} at the {city} trade show",
    "Behind the scenes: our {service_lower} team",
    "Questions we are often asked about {service_lower}",
]
