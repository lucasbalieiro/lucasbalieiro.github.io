use pulldown_cmark::{html, Options, Parser};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tera::{Context, Tera};
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PageMetadata {
    title: String,
    date: String,
    #[serde(default)]
    draft: Option<bool>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    image: Option<String>,
    #[serde(default)]
    image_caption: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TagIndex {
    tag: String,
    posts: Vec<PageMetadata>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let content_dir = "content";
    let build_dir = "public";
    let static_dir = "static";

    if Path::new(build_dir).exists() {
        fs::remove_dir_all(build_dir)?;
    }
    fs::create_dir_all(build_dir)?;

    let mut tera = Tera::new("src/templates/**/*.html")?;

    let mut tera_ctx = Context::new();

    let blog_index = build_blog_index(content_dir)?;
    tera_ctx.insert("blog_index", &blog_index);

    let blog_tag_index = build_tag_index(&blog_index);
    tera_ctx.insert("blog_tag_index", &blog_tag_index);

    for entry in WalkDir::new(content_dir).into_iter().filter_map(|e| e.ok()) {
        let file_path = entry.path();

        if let Some(extension) = file_path.extension().and_then(|s| s.to_str()) {
            if extension == "md" {
                process_md_file(&mut tera, &mut tera_ctx, file_path, content_dir, build_dir)?;
            }
        }
    }

    copy_static_files(static_dir, build_dir)?;

    generate_blog_index(&mut tera, &tera_ctx, build_dir, &blog_index)?;
    generate_tag_pages(&mut tera, &tera_ctx, build_dir, &blog_tag_index)?;

    println!("Site built successfully in {}!", build_dir);

    Ok(())
}

fn build_blog_index(content_dir: &str) -> Result<Vec<PageMetadata>, Box<dyn std::error::Error>> {
    let mut blog_index = Vec::new();

    for entry in WalkDir::new(content_dir).into_iter().filter_map(|e| e.ok()) {
        let file_path = entry.path();

        if file_path.extension().and_then(|s| s.to_str()) == Some("md")
            && file_path.to_str().unwrap().contains("/blog/")
        {
            let content = fs::read_to_string(file_path)?;

            if let Some(extracted) = matter::matter(&content) {
                let metadata: PageMetadata = toml::from_str(&extracted.0)?;

                let rel_path = file_path.strip_prefix(content_dir)?;

                let path_str = rel_path.with_extension("html").display().to_string();
                let path = if file_path.file_name().unwrap() == "index.md" {
                    format!("/{}/", rel_path.parent().unwrap().display())
                } else {
                    format!("/{}/", path_str.trim_end_matches(".html"))
                };

                let mut metadata = metadata;
                metadata.path = Some(path);

                let is_blog_index = rel_path.to_str().unwrap() == "blog/index.md"
                    || rel_path.to_str().unwrap() == "blog/tags/index.md";

                if !is_blog_index {
                    blog_index.push(metadata);
                }
            }
        }
    }

    blog_index.sort_by(|a, b| b.date.cmp(&a.date));

    Ok(blog_index)
}

fn build_tag_index(blog_posts: &[PageMetadata]) -> Vec<TagIndex> {
    let mut tag_map: HashMap<String, Vec<PageMetadata>> = HashMap::new();

    for post in blog_posts {
        for tag in &post.tags {
            tag_map.entry(tag.clone()).or_default().push(post.clone());
        }
    }

    let mut tag_index: Vec<TagIndex> = tag_map
        .into_iter()
        .map(|(tag, mut posts)| {
            posts.sort_by(|a, b| b.date.cmp(&a.date));
            TagIndex { tag, posts }
        })
        .collect();

    tag_index.sort_by(|a, b| a.tag.cmp(&b.tag));

    tag_index
}

fn process_md_file(
    tera: &mut Tera,
    tera_ctx: &mut Context,
    file_path: &Path,
    content_dir: &str,
    build_dir: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let content = fs::read_to_string(file_path)?;

    let (frontmatter, body) = match matter::matter(&content) {
        Some(extracted) => extracted,
        None => ("".to_string(), content.clone()),
    };

    let metadata: PageMetadata = if frontmatter.is_empty() {
        let filename = file_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("Untitled");

        PageMetadata {
            title: title_case(filename),
            date: "".to_string(),
            draft: None,
            path: None,
            image: None,
            image_caption: None,
            tags: vec![],
        }
    } else {
        toml::from_str(&frontmatter)?
    };

    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_FOOTNOTES);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TASKLISTS);

    let parser = Parser::new_ext(&body, options);
    let mut html_output = String::new();
    html::push_html(&mut html_output, parser);

    html_output = wrap_images_with_figcaption(&html_output);

    let rel_path = file_path.strip_prefix(content_dir)?;

    let output_path = if file_path.file_name().unwrap() == "index.md" {
        Path::new(build_dir)
            .join(rel_path.parent().unwrap())
            .join("index.html")
    } else {
        let path_str = rel_path.with_extension("html").display().to_string();
        Path::new(build_dir)
            .join(path_str.trim_end_matches(".html"))
            .join("index.html")
    };

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut ctx = tera_ctx.clone();
    ctx.insert("title", &metadata.title);
    ctx.insert("content", &html_output);
    ctx.insert("date", &metadata.date);
    ctx.insert("path", &metadata.path);
    ctx.insert("image", &metadata.image);
    ctx.insert("image_caption", &metadata.image_caption);
    ctx.insert("tags", &metadata.tags);

    let is_blog_post = rel_path.to_str().unwrap().starts_with("blog/")
        && rel_path.to_str().unwrap() != "blog/index.md";
    let is_index = rel_path.to_str().unwrap() == "index.md";

    let template_name = if is_index {
        "page.html"
    } else if is_blog_post {
        "post.html"
    } else {
        "page.html"
    };

    let rendered = tera.render(template_name, &ctx)?;
    fs::write(&output_path, rendered)?;

    println!("Generated: {}", output_path.display());

    Ok(())
}

fn copy_static_files(static_dir: &str, build_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !Path::new(static_dir).exists() {
        return Ok(());
    }

    for entry in WalkDir::new(static_dir).into_iter().filter_map(|e| e.ok()) {
        let file_path = entry.path();
        if file_path.is_file() {
            let rel_path = file_path.strip_prefix(static_dir)?;
            let dest_path = Path::new(build_dir).join(rel_path);

            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent)?;
            }

            fs::copy(file_path, &dest_path)?;
            println!("Copied: {}", dest_path.display());
        }
    }

    Ok(())
}

fn generate_blog_index(
    tera: &mut Tera,
    tera_ctx: &Context,
    build_dir: &str,
    blog_index: &[PageMetadata],
) -> Result<(), Box<dyn std::error::Error>> {
    let blog_dir = Path::new(build_dir).join("blog");
    fs::create_dir_all(&blog_dir)?;

    let index_path = blog_dir.join("index.html");

    let mut ctx = tera_ctx.clone();
    ctx.insert("title", &"Blog");
    ctx.insert("blog_index", blog_index);

    let rendered = tera.render("index.html", &ctx)?;
    fs::write(&index_path, rendered)?;

    println!("Generated: {}", index_path.display());

    Ok(())
}

fn generate_tag_pages(
    tera: &mut Tera,
    tera_ctx: &Context,
    build_dir: &str,
    tag_index: &[TagIndex],
) -> Result<(), Box<dyn std::error::Error>> {
    let tags_dir = Path::new(build_dir).join("blog").join("tags");
    fs::create_dir_all(&tags_dir)?;

    for tag in tag_index {
        let tag_page_dir = tags_dir.join(&tag.tag);
        fs::create_dir_all(&tag_page_dir)?;

        let index_path = tag_page_dir.join("index.html");

        let mut ctx = tera_ctx.clone();
        ctx.insert("title", &format!("Tag: {}", tag.tag));
        ctx.insert("tag", &tag.tag);
        ctx.insert("posts", &tag.posts);

        let rendered = tera.render("tag.html", &ctx)?;
        fs::write(&index_path, rendered)?;

        println!("Generated: {}", index_path.display());
    }

    Ok(())
}

fn title_case(s: &str) -> String {
    s.split('-')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().chain(chars).collect(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn wrap_images_with_figcaption(html: &str) -> String {
    let regex = regex::Regex::new(r#"<img([^>]*)title="([^"]*)"([^>]*)>"#).unwrap();
    regex.replace_all(html, |caps: &regex::Captures| {
        let before_title = &caps[1];
        let title = &caps[2];
        let after_title = &caps[3];
        format!(
            "<figure class=\"inline-image\"><img{}title=\"{}\"{}><figcaption>{}</figcaption></figure>",
            before_title, title, after_title, title
        )
    }).to_string()
}
