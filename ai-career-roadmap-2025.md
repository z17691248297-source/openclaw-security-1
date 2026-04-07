# 2025-2026 国内大厂 AI 岗位分析与学习路线

> 文档生成时间：2026 年 4 月
> 适用人群：高校学生、转行人员、在职工程师

---

## 一、国内大厂 AI 招聘岗位全景

### 1.1 主要招聘企业

| 公司 | AI 核心方向 | 代表产品/项目 |
|------|------------|--------------|
| **阿里巴巴** | 通义千问、多模态、电商 AI | 通义 App、淘宝推荐、阿里云百炼 |
| **腾讯** | 混元大模型、游戏 AI、广告推荐 | 腾讯混元、微信 AI、广告算法 |
| **字节跳动** | 豆包大模型、推荐算法、AIGC | 豆包、抖音推荐、剪映 AI |
| **百度** | 文心一言、自动驾驶、搜索 AI | 文心一言、Apollo、搜索推荐 |
| **华为** | 盘古大模型、昇腾 AI、终端 AI | 盘古、昇腾芯片、小艺助手 |
| **美团** | 配送优化、本地生活 AI | 智能调度、商家推荐 |
| **京东** | 供应链 AI、物流优化 | 智能仓储、京东言犀 |
| **小米** | 端侧 AI、IoT 智能 | 小爱同学、影像 AI |

### 1.2 核心岗位分类

#### 🎯 算法工程师（需求最大）
- **大模型算法工程师**：LLM 预训练/微调、RAG、Agent
- **推荐算法工程师**：召回、排序、多目标优化
- **计算机视觉工程师**：图像识别、目标检测、视频理解
- **NLP 算法工程师**：文本理解、对话系统、信息抽取
- **多模态算法工程师**：图文匹配、视频生成、跨模态检索

#### 🔧 工程/应用岗（增长最快）
- **大模型应用工程师**：LangChain、Agent 开发、API 集成
- **AI 基础设施工程师**：模型部署、推理优化、分布式训练
- **MLOps 工程师**：训练 pipeline、模型监控、自动化运维

#### 📊 数据/产品岗
- **数据科学家**：数据分析、AB 实验、策略优化
- **AI 产品经理**：需求分析、产品设计、效果评估

---

## 二、2025 年大厂技能要求分析

### 2.1 通用硬技能（所有岗位必备）

| 技能类别 | 具体内容 | 重要程度 |
|---------|---------|---------|
| **编程语言** | Python（精通）、C++（加分）、SQL | ⭐⭐⭐⭐⭐ |
| **深度学习框架** | PyTorch（主流）、TensorFlow | ⭐⭐⭐⭐⭐ |
| **机器学习基础** | 回归、分类、聚类、树模型、SVM | ⭐⭐⭐⭐⭐ |
| **深度学习基础** | CNN、RNN、Transformer、Attention | ⭐⭐⭐⭐⭐ |
| **数据结构与算法** | LeetCode 中等难度、常见算法题 | ⭐⭐⭐⭐ |
| **数学基础** | 线性代数、概率统计、微积分 | ⭐⭐⭐⭐ |

### 2.2 大模型方向核心技能（2025 热点）

| 技术领域 | 关键技术/工具 | 应用场景 |
|---------|-------------|---------|
| **RAG 系统** | LangChain, LlamaIndex, FAISS, Milvus, ElasticSearch | 企业知识库、智能问答 |
| **智能体开发** | ReAct, AutoGen, CrewAI, LangGraph | 任务自动化、多智能体协作 |
| **模型微调** | LoRA, QLoRA, SFT, DPO, PPO | 领域适配、对齐优化 |
| **多模态** | CLIP, BLIP2, OWL-ViT, Stable Diffusion | 图文理解、图像生成 |
| **部署优化** | FastAPI, Docker, Kubernetes, vLLM, Triton | 生产环境部署 |
| **主流模型** | Qwen2.5, LLaMA3, DeepSeek-VL, Mixtral | 开源模型应用 |

### 2.3 加分项

- 顶会论文（NeurIPS, ICML, CVPR, ACL 等）
- 开源项目贡献（GitHub star 100+）
- Kaggle/天池等竞赛获奖
- 大厂实习经历
- 垂直领域知识（医疗、法律、金融等）

---

## 三、完整学习路线（0 基础到就业）

### 📌 阶段一：编程与数学基础（1-2 个月）

#### 学习目标
- 掌握 Python 编程
- 理解核心数学概念
- 能独立完成基础编程任务

#### 学习内容

| 主题 | 具体内容 | 推荐资源 |
|-----|---------|---------|
| **Python 基础** | 语法、数据结构、函数、面向对象 | [B 站：Python 零基础入门](https://www.bilibili.com/video/BV1X7411X7Nz) |
| **NumPy/Pandas** | 数组操作、数据处理、数据清洗 | [B 站：NumPy 教程](https://www.bilibili.com/video/BV1KZ4y1x7YF) |
| **线性代数** | 矩阵运算、特征值、SVD | [3Blue1Brown 线性代数本质](https://www.bilibili.com/video/BV1ys411472E) |
| **概率统计** | 概率分布、假设检验、贝叶斯 | [B 站：概率论与数理统计](https://www.bilibili.com/video/BV1yA411y75f) |
| **微积分** | 导数、梯度、优化基础 | [3Blue1Brown 微积分本质](https://www.bilibili.com/video/BV1qW411N7oK) |

#### 实战项目
- 用 Python 实现数据分析小项目
- LeetCode 刷题 50+（重点：数组、字符串、链表）

---

### 📌 阶段二：机器学习基础（2-3 个月）

#### 学习目标
- 理解机器学习核心算法
- 能使用 sklearn 完成建模任务
- 掌握模型评估与调优方法

#### 学习内容

| 主题 | 具体内容 | 推荐资源 |
|-----|---------|---------|
| **监督学习** | 线性回归、逻辑回归、决策树、随机森林、SVM | [吴恩达机器学习](https://www.bilibili.com/video/BV19x411X7C6) |
| **无监督学习** | K-Means、PCA、层次聚类 | [李宏毅机器学习](https://www.bilibili.com/video/BV1TAtwzTE1S) |
| **模型评估** | 交叉验证、ROC/AUC、精确率/召回率 | 同上 |
| **特征工程** | 特征选择、特征变换、缺失值处理 | [B 站：特征工程实战](https://www.bilibili.com/video/BV1d54y1G7x8) |
| **集成学习** | Bagging、Boosting、XGBoost、LightGBM | [B 站：XGBoost 原理与实战](https://www.bilibili.com/video/BV1Wv411h7sN) |

#### 实战项目
- 泰坦尼克号生存预测（Kaggle）
- 房价预测项目
- 用户流失预测

---

### 📌 阶段三：深度学习（2-3 个月）

#### 学习目标
- 掌握神经网络基本原理
- 熟练使用 PyTorch 框架
- 能实现经典网络结构

#### 学习内容

| 主题 | 具体内容 | 推荐资源 |
|-----|---------|---------|
| **神经网络基础** | 感知机、反向传播、激活函数、损失函数 | [吴恩达深度学习](https://www.bilibili.com/video/BV1N9hVzkExw) |
| **PyTorch 框架** | Tensor、自动求导、Dataset、DataLoader | [PyTorch 深度学习实践](https://www.bilibili.com/video/BV1Y7411d7Ys) |
| **CNN** | 卷积、池化、ResNet、VGG、EfficientNet | [李宏毅深度学习](https://www.bilibili.com/video/BV1TAtwzTE1S) |
| **RNN/LSTM** | 序列建模、GRU、双向 RNN | 同上 |
| **Transformer** | Self-Attention、Encoder-Decoder、BERT | [B 站：Transformer 详解](https://www.bilibili.com/video/BV1pu411o7BE) |

#### 实战项目
- MNIST/CIFAR-10 图像分类
- 情感分析（IMDB 数据集）
- 文本生成（莎士比亚风格）

---

### 📌 阶段四：大模型与前沿技术（3-4 个月）⭐核心

#### 学习目标
- 理解大模型原理与架构
- 掌握 RAG、Agent 等应用技术
- 能独立完成大模型项目开发

#### 学习内容

| 主题 | 具体内容 | 推荐资源 |
|-----|---------|---------|
| **LLM 基础** | GPT 系列、LLaMA、训练范式 | [B 站：大模型基础教程](https://www.bilibili.com/video/BV1xbNbz9EqN) |
| **Prompt 工程** | Few-shot、CoT、ReAct、提示词优化 | [B 站：Prompt 工程实战](https://www.bilibili.com/video/BV1WmN5zLETY) |
| **RAG 系统** | 文档解析、向量数据库、检索优化 | [LangChain 官方教程](https://python.langchain.com/) |
| **智能体开发** | AutoGen、CrewAI、任务规划 | [B 站：Agent 开发实战](https://www.bilibili.com/video/BV1uNk1YxEJQ) |
| **模型微调** | LoRA、QLoRA、SFT、DPO | [B 站：大模型微调教程](https://www.bilibili.com/video/BV1PzL7zyEwD) |
| **多模态** | CLIP、Stable Diffusion、图文理解 | [B 站：多模态大模型](https://www.bilibili.com/video/BV1c5yrBcEEX) |

#### 实战项目（简历核心）

1. **企业文档智能问答系统**
   - 技术栈：RAG + LangChain + Milvus + Qwen2.5
   - 功能：支持 PDF/PPT 解析、语义检索、权限管理

2. **智能财报分析 Agent**
   - 技术栈：AutoGen + PDF 解析 + 数据可视化
   - 功能：自动提取财报指标、生成分析报告

3. **多模态图文问答系统**
   - 技术栈：CLIP + LLaMA3 + Docker
   - 功能：上传图片 + 问题，返回图文联合分析

4. **大模型部署系统**
   - 技术栈：FastAPI + Docker + Kubernetes + vLLM
   - 功能：模型打包、API 服务、弹性扩缩容

---

### 📌 阶段五：工程化与求职准备（1-2 个月）

#### 学习目标
- 掌握模型部署与优化
- 完成高质量简历项目
- 准备面试八股与算法题

#### 学习内容

| 主题 | 具体内容 |
|-----|---------|
| **模型部署** | ONNX、TensorRT、Triton Inference Server |
| **容器化** | Docker、Kubernetes 基础 |
| **API 开发** | FastAPI、Flask、RESTful 设计 |
| **性能优化** | 量化、剪枝、蒸馏、推理加速 |
| **面试准备** | LeetCode 200+、机器学习八股、项目复盘 |

---

## 四、精选学习资源汇总

### 4.1 视频课程（B 站）

| 课程 | UP 主/来源 | 链接 |
|-----|-----------|------|
| 吴恩达机器学习 | 搬运 | https://www.bilibili.com/video/BV19x411X7C6 |
| 吴恩达深度学习 | 搬运 | https://www.bilibili.com/video/BV1N9hVzkExw |
| 李宏毅机器学习 2025 | 李宏毅 | https://www.bilibili.com/video/BV1TAtwzTE1S |
| PyTorch 深度学习实践 | 刘二大人 | https://www.bilibili.com/video/BV1Y7411d7Ys |
| AI 大模型全套教程 | 咕泡科技 | https://www.bilibili.com/video/BV1xbNbz9EqN |
| 深度学习 348 集 | - | https://www.bilibili.com/video/BV1PzL7zyEwD |
| 大模型实战 LangChain | - | https://www.bilibili.com/video/BV1WmN5zLETY |
| 神经网络与深度学习 | 黑马程序员 | https://www.bilibili.com/video/BV1c5yrBcEEX |

### 4.2 文档与书籍

| 类型 | 名称 | 链接 |
|-----|------|------|
| 在线课程 | 吴恩达 Coursera 专项课 | https://www.coursera.org/specializations/deep-learning |
| 书籍 | 《深度学习》（花书） | 经典理论 |
| 书籍 | 《动手学深度学习》 | https://zh.d2l.ai/ |
| 文档 | LangChain 官方文档 | https://python.langchain.com/ |
| 文档 | Hugging Face 教程 | https://huggingface.co/learn |
| 仓库 | AI 算法岗求职攻略 | https://github.com/amusi/AI-Job-Notes |
| 仓库 | AI 学习路线图 | https://github.com/tangyudi/Ai-learn |

### 4.3 实践平台

| 平台 | 用途 | 链接 |
|-----|------|------|
| Kaggle | 数据科学竞赛 | https://www.kaggle.com/ |
| 阿里天池 | 国内竞赛平台 | https://tianchi.aliyun.com/ |
| LeetCode | 算法刷题 | https://leetcode.cn/ |
| Hugging Face | 模型与数据集 | https://huggingface.co/ |
| ModelScope | 阿里模型开放平台 | https://modelscope.cn/ |
| 飞桨 AI Studio | 百度学习平台 | https://aistudio.baidu.com/ |

---

## 五、求职时间规划建议

### 校招（针对在校生）

| 时间 | 事项 |
|-----|------|
| 3-6 月 | 日常实习投递 |
| 7-8 月 | 暑期实习入职 |
| 8-10 月 | 秋招提前批 |
| 9-11 月 | 秋招正式批 |
| 次年 3-5 月 | 春招补录 |

### 社招（针对转行/在职）

| 时间 | 事项 |
|-----|------|
| 第 1-3 月 | 基础学习（Python+ 机器学习） |
| 第 4-6 月 | 深度学习 + 项目实战 |
| 第 7-9 月 | 大模型技术 + 核心项目 |
| 第 10-12 月 | 工程化 + 简历优化 + 面试准备 |

---

## 六、面试高频考点

### 6.1 机器学习基础
- 过拟合与欠拟合、正则化方法
- 决策树分裂准则（信息增益、基尼系数）
- SVM 原理、核函数
- XGBoost/LightGBM 原理与区别
- 特征工程方法

### 6.2 深度学习
- 反向传播推导
- CNN 经典网络（ResNet、VGG）
- Transformer 架构详解
- Attention 机制
- 梯度消失/爆炸解决方案

### 6.3 大模型方向
- LLM 训练流程（预训练、SFT、RLHF）
- RAG 原理与优化
- LoRA 微调原理
- Prompt 工程技巧
- Agent 架构设计

### 6.4 代码题
- LeetCode 中等难度（数组、链表、树、动态规划）
- 手推常见算法（K-Means、逻辑回归梯度）
- PyTorch 实现简单网络

---

## 七、薪资参考（2025 年）

| 岗位 | 应届/初级 | 中级（3-5 年） | 高级（5 年+） |
|-----|---------|-------------|------------|
| 算法工程师 | 25-45w | 50-80w | 80-150w+ |
| 大模型工程师 | 30-50w | 60-100w | 100-200w+ |
| AI 应用工程师 | 20-35w | 40-70w | 70-120w |
| 数据科学家 | 25-40w | 50-80w | 80-150w |

*注：薪资因公司、地区、个人能力差异较大，仅供参考*

---

## 八、学习建议

1. **不要只看不练**：每个知识点都要配合代码实践
2. **项目驱动学习**：用项目串联知识点，简历才有亮点
3. **关注前沿动态**：订阅 Arxiv、Hugging Face 博客
4. **参与开源社区**：GitHub 贡献是加分项
5. **建立知识体系**：用笔记工具（Notion/Obsidian）整理知识
6. **找学习伙伴**：加入学习群、参加线下 meetup

---

## 九、常用工具速查

```bash
# Python 环境
conda create -n ai python=3.10
conda activate ai

# 深度学习框架
pip install torch torchvision torchaudio
pip install transformers datasets
pip install langchain langchain-community

# 向量数据库
pip install faiss-cpu chromadb
# 或安装 Milvus

# 大模型相关
pip install accelerate peft bitsandbytes
pip install auto-gptq optimum

# 部署工具
pip install fastapi uvicorn
pip install docker kubernetes
```

---

**祝学习顺利，早日拿到心仪的 Offer！** 🎉

---

*文档参考来源：*
- *https://developer.aliyun.com/article/1661114*
- *https://github.com/amusi/AI-Job-Notes*
- *https://github.com/tangyudi/Ai-learn*
- *各公司官方招聘页面*
